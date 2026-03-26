import os
from dotenv import load_dotenv

load_dotenv()

# Gmail Configuration
OAUTH_CREDENTIALS_FILE = os.getenv("OAUTH_CREDENTIALS_FILE", "credenciales.json")
GMAIL_REFRESH_TOKEN = os.getenv("GMAIL_REFRESH_TOKEN", "")
GMAIL_SENDER_FILTER = os.getenv("GMAIL_SENDER_FILTER", "jose.geeksjose@gmail.com")
GMAIL_QUERY = os.getenv("GMAIL_QUERY", f"from:{GMAIL_SENDER_FILTER} newer_than:7d")
POLLING_INTERVAL = int(os.getenv("POLLING_INTERVAL", "60"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "5"))

# Database Configuration
DB_PATH = os.getenv("DB_PATH", "data/collector.db")

# Ingestion Configuration
INGESTION_ENDPOINT = os.getenv("INGESTION_ENDPOINT", "")
INGESTION_API_KEY = os.getenv("INGESTION_API_KEY", "")

# Google API Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
