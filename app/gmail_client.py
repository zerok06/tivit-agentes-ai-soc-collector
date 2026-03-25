import base64
from google.oauth2 import service_account
from googleapiclient.discovery import build
from app.config import SERVICE_ACCOUNT_FILE, DELEGATED_USER, SCOPES, GMAIL_QUERY
from app.logger import logger

def get_gmail_service():
    try:
        creds = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE,
            scopes=SCOPES
        )
        delegated_creds = creds.with_subject(DELEGATED_USER)
        service = build('gmail', 'v1', credentials=delegated_creds)
        return service
    except Exception as e:
        logger.error(f"Error initializing Gmail service: {e}")
        return None

def fetch_messages(service):
    try:
        results = service.users().messages().list(userId='me', q=GMAIL_QUERY).execute()
        return results.get('messages', [])
    except Exception as e:
        logger.error(f"Error listing messages: {e}")
        return []

def get_message_details(service, msg_id):
    try:
        message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        payload = message.get('payload', {})
        headers = payload.get('headers', [])
        
        subject = ""
        sender = ""
        for header in headers:
            if header.get('name') == 'Subject':
                subject = header.get('value')
            if header.get('name') == 'From':
                sender = header.get('value')
        
        # Extract full body
        body = ""
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body'].get('data')
                    if data:
                        body = base64.urlsafe_b64decode(data).decode('utf-8')
                        break
        else:
            data = payload.get('body', {}).get('data')
            if data:
                body = base64.urlsafe_b64decode(data).decode('utf-8')

        return {
            "id": msg_id,
            "subject": subject,
            "sender": sender,
            "snippet": message.get('snippet', ''),
            "body": body
        }
    except Exception as e:
        logger.error(f"Error fetching message details for {msg_id}: {e}")
        return None
