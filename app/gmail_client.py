import base64
import json
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from app.config import OAUTH_CREDENTIALS_FILE, GMAIL_REFRESH_TOKEN, SCOPES, GMAIL_QUERY
from app.logger import logger

def get_gmail_service():
    try:
        if not GMAIL_REFRESH_TOKEN:
            logger.error("GMAIL_REFRESH_TOKEN is empty. Cannot authenticate.")
            return None

        # Leer client_id y client_secret del archivo credenciales.json
        with open(OAUTH_CREDENTIALS_FILE, 'r') as f:
            creds_data = json.load(f)
            
        # Dependiendo del tipo de app OAuth (installed o web)
        creds_type = 'installed' if 'installed' in creds_data else 'web'
        client_id = creds_data[creds_type]['client_id']
        client_secret = creds_data[creds_type]['client_secret']
        token_uri = creds_data[creds_type]['token_uri']

        creds = Credentials(
            token=None,
            refresh_token=GMAIL_REFRESH_TOKEN,
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=SCOPES
        )

        service = build('gmail', 'v1', credentials=creds)
        return service
    except Exception as e:
        logger.error(f"Error initializing Gmail service (OAuth): {e}")
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
