import unittest
import os
os.environ["DB_PATH"] = ":memory:"

from app.parser import parse_incident_email
from app.db import init_db, is_processed, save_processed_email, cleanup_old_data, get_connection
import sqlite3

class TestCollector(unittest.TestCase):
    def setUp(self):
        # Use an in-memory database for testing
        os.environ["DB_PATH"] = ":memory:"
        init_db()

    def test_parser_standard(self):
        body = """
Solicitante: IPS - SIEM
Categoría: 183 - Solicitud Ciberseguridad
Subcategoría: 865 - SIEM
Tercer nivel: 4180 - Evento
Descripción: AVISO: Mensagem Externa. Rule Name: CHA - High - AWS - USER DELETE
"""
        details = {
            "id": "msg123",
            "subject": "CHA - High - AWS - R174396 - USER DELETE Fired",
            "sender": "alerts@security.com",
            "body": body,
            "snippet": "AVISO: Mensagem Externa."
        }
        parsed = parse_incident_email(details)
        self.assertEqual(parsed['ticket_id'], "R174396")
        self.assertEqual(parsed['provider'], "SensrIT")
        self.assertEqual(parsed['severidad'], "High")
        self.assertEqual(parsed['domain'], "AWS")
        self.assertEqual(parsed['requester'], "IPS - SIEM")
        self.assertEqual(parsed['category'], "183 - Solicitud Ciberseguridad")
        self.assertIn("AVISO: Mensagem Externa", parsed['payload'])

    def test_parser_no_ticket(self):
        details = {
            "id": "msg456",
            "subject": "General Alert - No Ticket Here",
            "sender": "alerts@security.com",
            "snippet": "Something happened"
        }
        parsed = parse_incident_email(details)
        self.assertEqual(parsed['ticket_id'], "N/A")

    def test_db_deduplication(self):
        msg_id = "test_msg_1"
        self.assertFalse(is_processed(msg_id))
        save_processed_email(msg_id, ticket_id="INC123", subject="Test", sender="user@test.com")
        self.assertTrue(is_processed(msg_id))

    def test_db_retention(self):
        msg_id = "old_msg"
        # Manually insert an old record
        with get_connection() as conn:
            conn.execute("""
                INSERT INTO processed_emails (message_id, processed_at) 
                VALUES (?, datetime('now', '-8 days'))
            """, (msg_id,))
        
        self.assertTrue(is_processed(msg_id))
        cleanup_old_data(days=7)
        self.assertFalse(is_processed(msg_id))

if __name__ == "__main__":
    unittest.main()
