import sqlite3
import os
from app.config import DB_PATH
from app.logger import logger

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for better performance
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS processed_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                ticket_id TEXT,
                subject TEXT,
                sender TEXT,
                processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT,
                error TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_message_id ON processed_emails(message_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_processed_at ON processed_emails(processed_at);")
        logger.info("Database initialized")

def is_processed(message_id):
    with get_connection() as conn:
        cursor = conn.execute("SELECT 1 FROM processed_emails WHERE message_id = ?", (message_id,))
        return cursor.fetchone() is not None

def save_processed_email(message_id, ticket_id=None, subject=None, sender=None, status="success", error=None):
    try:
        with get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO processed_emails (message_id, ticket_id, subject, sender, status, error)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (message_id, ticket_id, subject, sender, status, error))
    except Exception as e:
        logger.error(f"Error saving to database: {e}")

def cleanup_old_data(days=7):
    try:
        with get_connection() as conn:
            conn.execute("DELETE FROM processed_emails WHERE processed_at < datetime('now', ?)", (f'-{days} days',))
            conn.execute("VACUUM;")
            logger.info(f"Cleanup performed: removed data older than {days} days")
    except Exception as e:
        logger.error(f"Error cleaning up database: {e}")
