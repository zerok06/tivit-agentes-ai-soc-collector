import re
import json
from app.logger import logger

def extract_field(text, label):
    pattern = rf"{label}:\s*(.*)"
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else ""

def parse_incident_email(message_details):
    try:
        subject = message_details.get('subject', '')
        body = message_details.get('body', '')
        if not body:
            body = message_details.get('snippet', '')
        
        # Extract labeled fields from body
        solicitante = extract_field(body, "Solicitante")
        categoria = extract_field(body, "Categoría")
        subcategoria = extract_field(body, "Subcategoría")
        tercer_nivel = extract_field(body, "Tercer nivel")
        descripcion = extract_field(body, "Descripción")
        
        # Regex for Ticket ID (Example: R174396, INC0012345, or TKT-123)
        # Search in subject AND body
        ticket_id_match = re.search(r'([R|INC]\d+|TKT-\d+)', subject + " " + body, re.IGNORECASE)
        ticket_id = ticket_id_match.group(1) if ticket_id_match else "N/A"
        
        # Parse subject components for domain/severidad fallback
        subject_parts = [p.strip() for p in subject.split('-')]
        domain = ""
        severidad = ""
        
        if len(subject_parts) >= 3:
            severidad = subject_parts[1]
            domain = subject_parts[2]

        return {
            "ticket_id": ticket_id,
            "provider": "SensrIT",
            "subject": subject,
            "domain": domain,
            "severidad": severidad,
            "requester": solicitante if solicitante else "IPS - SIEM",
            "category": categoria if categoria else "183 - Solicitud Ciberseguridad",
            "subcategory": subcategoria if subcategoria else "865 - SIEM",
            "third_level": tercer_nivel if tercer_nivel else "4180 - Evento",
            "payload": descripcion if descripcion else body
        }
    except Exception as e:
        logger.error(f"Error parsing email: {e}")
        return None
