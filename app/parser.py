import re
import json
from app.logger import logger

def extract_field(pattern, text, flags=re.IGNORECASE, default="N/A"):
    """Helper method to execute a regex search and return the first capture group safely."""
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else default

def parse_incident_email(message_details):
    try:
        email_subject = message_details.get('subject', '')
        body = message_details.get('body', '')
        if not body:
            body = message_details.get('snippet', '')
            
        # Paso 1: Normalizar texto
        # Consolidamos el texto para búsquedas globales
        text = email_subject + "\n" + body
        
        # Paso 2: Extraer bloques principales
        
        # 🔹 Ticket ID (más permisivo a R123 o ticket R123 o INC123)
        ticket_id = extract_field(r"(?:ticket\s+)?((?:R|INC)\d+|TKT-\d+)", text)
        
        # 🔹 Campos básicos del cuerpo
        asunto_body = extract_field(r"Asunto:\s*(.+)", body)
        solicitante = extract_field(r"Solicitante:\s*(.+)", body)
        categoria   = extract_field(r"Categoría:\s*(.+)", body)
        subcategoria= extract_field(r"Subcategoría:\s*(.+)", body)
        tercer_nivel= extract_field(r"Tercer nivel:\s*(.+)", body)
        
        # El Subject real viene de "Asunto" en el body, o del subject del email como fallback
        asunto_raw = asunto_body if asunto_body != "N/A" else (email_subject if email_subject else "N/A")

        # 🔹 Descripción y Payload (bloque grande)
        # 1. Intento robusto: Busca desde Descripción, garantizando que incluya 'Payload:'
        payload = extract_field(r"Descripción:\s*(.*?Payload:\s*[\s\S]+)", body, flags=re.IGNORECASE|re.DOTALL)
        if payload == "N/A":
            # 2. Intento limpiando cabecera de advertencia (AVISO: ... CLST)
            payload = extract_field(r"Descripción:\s*(?:AVISO:.*?CLST\s*)([\s\S]+)", body, flags=re.IGNORECASE|re.DOTALL)
        if payload == "N/A":
            # 3. Fallback: Capturamos todo desde Descripción
            payload = extract_field(r"Descripción:\s*([\s\S]+)", body, flags=re.IGNORECASE|re.DOTALL)

        # Paso 3: Derivar campos del Asunto
        # Ejemplo: PROAN - HIGH - FW - SUCCESSFUL - OUTBOUND TRAFFIC...
        domain = "N/A"
        severidad = "N/A"
        clean_subject = asunto_raw

        m = re.search(r"^(\w+)\s*-\s*(\w+)\s*-\s*(\w+)\s*-\s*(.+)", asunto_raw)
        if m:
            domain = m.group(1).strip()
            severidad = m.group(2).strip()
            # clean_subject = dominio_tecnico - texto real
            clean_subject = f"{m.group(3).strip()} - {m.group(4).strip()}"
        else:
            # Fallback simple si no hace match completo pero tiene los guiones
            subject_parts = [p.strip() for p in asunto_raw.split('-')]
            if len(subject_parts) >= 3:
                severidad = subject_parts[1]
                domain = subject_parts[2]

        return {
            "ticket_id": ticket_id,
            "provider": "SensrIT",
            "domain": domain,
            "severidad": severidad,
            "subject": clean_subject,
            "requester": solicitante,
            "category": categoria,
            "subcategory": subcategoria,
            "third_level": tercer_nivel,
            "payload": payload if payload != "N/A" else (body if body else "N/A")
        }
            
    except Exception as e:
        logger.error(f"Error parsing email: {e}")
        return None

