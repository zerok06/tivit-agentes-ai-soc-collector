import requests
from app.config import INGESTION_ENDPOINT, INGESTION_API_KEY
from app.logger import logger

def send_to_ingestion(payload):
    if not INGESTION_ENDPOINT:
        logger.warning("Ingestion endpoint not configured. Skipping send.")
        return False
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": INGESTION_API_KEY
    }
    
    try:
        print("---------------")
        print(payload)
        print("---------------")
        response = requests.post(
            INGESTION_ENDPOINT,
            json=payload,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        logger.info(f"Data sent successfully for ticket {payload.get('ticket_id')}")
        return True
    except Exception as e:
        logger.error(f"Failed to send data to ingestion: {e}")
        return False
