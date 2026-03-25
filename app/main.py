import time
from app.config import POLLING_INTERVAL
from app.logger import logger
from app.db import init_db, cleanup_old_data, is_processed, save_processed_email
from app.gmail_client import get_gmail_service, fetch_messages, get_message_details
from app.parser import parse_incident_email
from app.sender import send_to_ingestion

def process_emails():
    logger.info("Starting email processing cycle")
    
    # 1. Cleanup old data (7 days)
    cleanup_old_data(days=7)
    
    # 2. Initialize Gmail service
    service = get_gmail_service()
    if not service:
        logger.error("Could not initialize Gmail service. Skipping cycle.")
        return

    # 3. Fetch messages
    messages = fetch_messages(service)
    if not messages:
        logger.info("No new messages found.")
        return
    
    count_processed = 0
    count_skipped = 0
    count_errors = 0

    for msg in messages:
        msg_id = msg['id']
        
        # 4. Deduplication level 1: Check if already processed
        if is_processed(msg_id):
            count_skipped += 1
            continue
            
        # 5. Get full details
        details = get_message_details(service, msg_id)
        if not details:
            count_errors += 1
            continue
            
        # 6. Parse message
        parsed_data = parse_incident_email(details)
        if not parsed_data:
            save_processed_email(msg_id, status="error", error="Parsing failed")
            count_errors += 1
            continue
            
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
        
        if sent_success:
            count_processed += 1
        else:
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
