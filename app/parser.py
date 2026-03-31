import re
import json
from app.logger import logger

def clean_value(val):
    """Limpia espacios invisibles y quita asteriscos de Markdown solo en los bordes extremos."""
    if not val:
        return "N/A"
    val = val.strip()
    val = re.sub(r'^\*+|\*+$', '', val)
    return val.strip() if val.strip() else "N/A"

def normalize_text(text, labels):
    """Normalización FUERTE del cuerpo para forzar saltos estructurales y limpiar ruido."""
    if not text:
        return ""
    text = text.replace('\xa0', ' ')
    
    # Forzar saltos de línea garantizados antes de etiquetas importantes
    # (Incluso si están pegadas tras otra palabra o tienen Markdown alrededor)
    for label in labels:
        text = re.sub(rf"\s*[\*\_]*{label}[\*\_]*\s*:", f"\n{label}: ", text, flags=re.IGNORECASE)

    # Limpiar múltiples saltos
    text = re.sub(r"\n+", "\n", text)
    return text.strip()

def parse_incident_email(message_details):
    try:
        email_subject = message_details.get('subject', '')
        raw_body = message_details.get('body', '')
        if not raw_body:
            raw_body = message_details.get('snippet', '')
            
        labels = ["Asunto", "Solicitante", "Categoría", "Subcategoría", "Tercer nivel", "Descripción"]
        
        # 1. Normalización Fuerte
        # Esto soluciona problemas de etiquetas pegadas (Ej: "Solicitante: X Categoría: Y")
        body = normalize_text(raw_body, labels)
        
        text_global = email_subject + "\n" + body
        
        # 2. Extraer Ticket ID (Búsqueda global flexible)
        ticket_match = re.search(r"(?:ticket\s+)?((?:R|INC)\d+|TKT-\d+)", text_global, re.IGNORECASE)
        ticket_id = ticket_match.group(1) if ticket_match else "N/A"
        
        # 3. EXTRACCIÓN EN BLOQUES
        positions = []
        for label in labels:
            # Como normalize_text ya forzó \n y dejó limpios los labels, la búsqueda es simple y exacta
            pattern = rf"(?:^|\n){label}\s*:\s*"
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                positions.append({
                    "label": label,
                    "start": match.end(),
                    "match_start": match.start()
                })
                
        positions.sort(key=lambda x: x["match_start"])
        extracted_data = {l: "N/A" for l in labels}
        
        # Extraer el contenido entre posiciones
        for i in range(len(positions)):
            current = positions[i]
            start_idx = current["start"]
            
            if i + 1 < len(positions):
                end_idx = positions[i+1]["match_start"]
                content = body[start_idx:end_idx]
            else:
                content = body[start_idx:]
                
            extracted_data[current["label"]] = clean_value(content)
            
        # 4. Derivar campos del Asunto
        asunto_raw = extracted_data["Asunto"]
        if asunto_raw == "N/A" and email_subject:
            asunto_raw = clean_value(email_subject)
            
        domain = "N/A"
        severidad = "N/A"
        clean_subject = asunto_raw

        # Regex inteligente para el Subject (más estricta para evitar contaminar con texto basura)
        m = re.search(r"^(\w+)\s*-\s*(HIGH|MEDIUM|LOW|CRITICAL)\s*-\s*(.+)", asunto_raw, re.IGNORECASE)
        if m:
            domain = m.group(1).strip().upper()
            severidad = m.group(2).strip().upper()
            clean_subject = m.group(3).strip()
        else:
            # Fallback simple
            subject_parts = [p.strip() for p in asunto_raw.split('-')]
            if len(subject_parts) >= 3:
                severidad = subject_parts[1].upper()
                domain = subject_parts[2].upper()

        # Fallback recomendado por si Categoría quedó vacía
        if extracted_data["Categoría"] == "N/A":
            cat_match = re.search(r"Categoría:\s*(.+)", text_global, re.IGNORECASE)
            if cat_match:
                extracted_data["Categoría"] = clean_value(cat_match.group(1))

        # 5. Tratamiento del Payload
        payload = extracted_data["Descripción"]
        if payload != "N/A":
            # Caso ideal
            explicit_payload = re.search(r"(Payload:\s*[\s\S]+)", payload, re.IGNORECASE)
            if explicit_payload:
                payload = explicit_payload.group(1).strip()
            else:
                # Buscar inicio real del evento (QRadar, fecha, o Rule Name)
                alt_match = re.search(r"(Rule Name:[\s\S]+|date=\d{4}-\d{2}-\d{2}[\s\S]+)", payload, re.IGNORECASE)
                if alt_match:
                    payload = alt_match.group(1).strip()
                else:
                    # Limpiar la cabecera AVISO si existe
                    aviso_match = re.search(r"AVISO:.*?CLST\s*([\s\S]+)", payload, re.IGNORECASE|re.DOTALL)
                    if aviso_match:
                        payload = aviso_match.group(1).strip()

        return {
            "ticket_id": ticket_id,
            "provider": "SensrIT",
            "domain": domain,
            "severidad": severidad,
            "subject": clean_subject,
            "requester": extracted_data["Solicitante"],
            "category": extracted_data["Categoría"],
            "subcategory": extracted_data["Subcategoría"],
            "third_level": extracted_data["Tercer nivel"],
            "payload": payload if payload != "N/A" else (raw_body if raw_body else "N/A")
        }
            
    except Exception as e:
        logger.error(f"Error parsing email en bloques: {e}")
        return None

