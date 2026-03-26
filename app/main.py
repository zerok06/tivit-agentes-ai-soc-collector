import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.config import POLLING_INTERVAL, MAX_WORKERS
from app.logger import logger
from app.db import init_db, cleanup_old_data, is_processed, save_processed_email
from app.gmail_client import get_gmail_service, fetch_messages, get_message_details
from app.parser import parse_incident_email
from app.sender import send_to_ingestion

def process_single_message(msg_id):
    # 4. Deduplication level 1: Check if already processed
    if is_processed(msg_id):
        return "skipped"
        
    # Cada hilo obtiene su propia instancia de servicio de Gmail (evita errores de concurrencia)
    service = get_gmail_service()
    if not service:
        return "error"
        
    # 5. Get full details
    details = get_message_details(service, msg_id)
    if not details:
        return "error"
        
    # 6. Parse message
    parsed_data = parse_incident_email(details)
    if not parsed_data:
        save_processed_email(msg_id, status="error", error="Parsing failed")
        return "error"
        
    # 7. Send to ingestion
    sent_success = send_to_ingestion(parsed_data)
    
    # 8. Save to DB (Local tracking)
    status = "success" if sent_success else "send_failed"
    save_processed_email(
        msg_id, 
        ticket_id=parsed_data.get('ticket_id'),
        subject=details.get('subject'),
        sender=details.get('sender'),
        status=status
    )
    return "success" if sent_success else "error"

last_cleanup_time = 0

def process_emails():
    global last_cleanup_time
    logger.info("Starting email processing cycle")
    
    # 1. Cleanup old data (7 days) only once every 24 hours to save resources
    current_time = time.time()
    if current_time - last_cleanup_time > 86400: # 24 hours in seconds
        cleanup_old_data(days=7)
        last_cleanup_time = current_time
    
    # 2. Initialize main Gmail service for listing
    main_service = get_gmail_service()
    if not main_service:
        logger.error("Could not initialize main Gmail service. Skipping cycle.")
        return

    # 3. Fetch list of messages
    messages = fetch_messages(main_service)
    if not messages:
        logger.info("No new messages found.")
        return
    
    count_processed = 0
    count_skipped = 0
    count_errors = 0

    # Procesamiento en lotes (concurrente) con MAX_WORKERS hilos
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Enviamos todas las tareas al pool de hilos
        futures = {executor.submit(process_single_message, msg['id']): msg for msg in messages}
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if result == "success":
                    count_processed += 1
                elif result == "skipped":
                    count_skipped += 1
                else:
                    count_errors += 1
            except Exception as e:
                logger.error(f"Worker generated an exception: {e}")
                count_errors += 1

    logger.info(f"Cycle completed: {count_processed} processed, {count_skipped} skipped, {count_errors} errors")
def main():
    logger.info("AI SOC Collector starting up...")
    init_db()
    
    while True:
        try:
            process_emails()
        except KeyboardInterrupt:
            logger.info("Service stopping...")
            break
        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")
        
        logger.info(f"Sleeping for {POLLING_INTERVAL}s...")
        time.sleep(POLLING_INTERVAL)

if __name__ == "__main__":
    main()
