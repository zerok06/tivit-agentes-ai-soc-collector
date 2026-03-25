import os
from dotenv import load_dotenv

load_dotenv()

# Gmail Configuration
SERVICE_ACCOUNT_FILE = os.getenv("SERVICE_ACCOUNT_FILE", "credenciales.json")
DELEGATED_USER = os.getenv("DELEGATED_USER", "jose.paye@tivit.com")
GMAIL_QUERY = os.getenv("GMAIL_QUERY", "newer_than:7d")
POLLING_INTERVAL = int(os.getenv("POLLING_INTERVAL", "60"))

# Database Configuration
DB_PATH = os.getenv("DB_PATH", "data/collector.db")

# Ingestion Configuration
INGESTION_ENDPOINT = os.getenv("INGESTION_ENDPOINT", "")
INGESTION_API_KEY = os.getenv("INGESTION_API_KEY", "")

# Google API Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
