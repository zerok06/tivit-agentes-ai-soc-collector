import re
import json
from app.logger import logger

def extract_field(text, label, is_last=False):
    # Si is_last es True, captura todo hasta el final (incluyendo saltos de línea con re.DOTALL)
    flags = re.IGNORECASE | re.DOTALL if is_last else re.IGNORECASE
    pattern = rf"{label}:\s*(.*)"
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else "N/A"

def parse_incident_email(message_details):
    try:
        email_subject = message_details.get('subject', '')
        body = message_details.get('body', '')
        if not body:
            body = message_details.get('snippet', '')
        
        # Extract labeled fields from body
        asunto_body = extract_field(body, "Asunto")
        solicitante = extract_field(body, "Solicitante")
        categoria = extract_field(body, "Categoría")
        subcategoria = extract_field(body, "Subcategoría")
        tercer_nivel = extract_field(body, "Tercer nivel")
        descripcion = extract_field(body, "Descripción", is_last=True)
        
        # El Subject con los datos reales asiste en el cuerpo como "Asunto: ..."
        actual_subject = asunto_body if asunto_body != "N/A" else (email_subject if email_subject else "N/A")

        # Regex for Ticket ID (Example: R174396, INC0012345, or TKT-123)
        # Search in email_subject AND body
        ticket_id_match = re.search(r'((?:R|INC)\d+|TKT-\d+)', email_subject + " " + body, re.IGNORECASE)
        ticket_id = ticket_id_match.group(1) if ticket_id_match else "N/A"
        
        # Parse subject components for domain/severidad fallback
        # Example: "CHA - High - AWS - Modified Role Fired"
        subject_parts = [p.strip() for p in actual_subject.split('-')]
        domain = "N/A"
        severidad = "N/A"
        
        if len(subject_parts) >= 3:
            severidad = subject_parts[1] if subject_parts[1] else "N/A"
            domain = subject_parts[2] if subject_parts[2] else "N/A"

        return {
            "ticket_id": ticket_id,
            "provider": "SensrIT",
            "subject": actual_subject,
            "domain": domain,
            "severidad": severidad,
            "requester": solicitante,
            "category": categoria,
            "subcategory": subcategoria,
            "third_level": tercer_nivel,
            "payload": descripcion if descripcion != "N/A" else (body if body else "N/A")
        }
    except Exception as e:
        logger.error(f"Error parsing email: {e}")
        return None

