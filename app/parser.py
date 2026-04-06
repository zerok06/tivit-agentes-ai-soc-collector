"""
parser.py - Extractor robusto de incidentes SOC desde correo electronico.

Campos objetivo:
    ticket_id, descripcion_full, rule_name, source_ip,
    destination_ip, payload, domain, severity

Estrategia de dos pasos:
  1. Normalizar etiquetas del sobre (Asunto, Descripcion, etc.)
  2. Normalizar etiquetas internas de la descripcion (Rule Name, Source IP, etc.)
     => Resuelve el caso real donde el email llega como bloque continuo sin saltos.
  3. Aplicar regex multiline seguras con ^ para evitar falsos positivos en payload.
"""

import re
from app.logger import logger


# ---------------------------------------------------------------------------
# Etiquetas estructurales del sobre del ticket
# ---------------------------------------------------------------------------

STRUCTURAL_LABELS = [
    "Asunto",
    "Solicitante",
    "Categoria",
    "Subcategoria",
    "Tercer nivel",
    "Descripcion",
]

# Alias con tilde para compatibilidad
STRUCTURAL_LABELS_TILDE = [
    "Asunto",
    "Solicitante",
    "Categor\u00eda",
    "Subcategor\u00eda",
    "Tercer nivel",
    "Descripci\u00f3n",
]

# Etiquetas internas del bloque de Descripcion (campos QRadar/FortiGate).
# El orden IMPORTA: Payload SIEMPRE al final para capturar todo lo que sigue.
DESCRIPTION_INTERNAL_LABELS = [
    "Rule Name",
    "Rule Description",
    "Source IP",
    "Source Port",
    "Source Username (from event)",
    "Source Network",
    "Destination IP",
    "Destination Port",
    "Destination Username (from Account Name)",
    "Destination Network",
    "Protocol",
    "QID",
    "Event Name",
    "Event Description",
    "Category",
    "Log Source ID",
    "Log Source Name",
    "Payload",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first(match, group=1):
    """Retorna el grupo del match o None si no hay match."""
    return match.group(group).strip() if match else None


def _clean(val, default="N/A"):
    """Limpia espacios y asteriscos de Markdown en los bordes."""
    if not val:
        return default
    val = str(val).strip()
    val = re.sub(r"^\*+|\*+$", "", val).strip()
    return val if val else default


def _normalize_body(text, labels_with_tilde):
    """
    Normalizacion FUERTE del cuerpo del email.
    Fuerza saltos de linea antes de cada etiqueta estructural del sobre.
    Trabaja con etiquetas con y sin tilde.
    """
    if not text:
        return ""

    text = text.replace("\xa0", " ")

    for label in labels_with_tilde:
        text = re.sub(
            rf"\s*[\*\_]*{re.escape(label)}[\*\_]*\s*:",
            "\n" + label + ":",
            text,
            flags=re.IGNORECASE,
        )

    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def _normalize_description(text):
    """
    Fuerza saltos de linea antes de cada etiqueta interna del bloque Descripcion.

    CRITICO: Resuelve el caso real donde la descripcion llega como un unico bloque
    continuo sin saltos de linea entre Rule Name:, Source IP:, Payload:, etc.
    Solo agrega el salto si NO habia ya un salto justo antes.
    """
    if not text:
        return ""

    for label in DESCRIPTION_INTERNAL_LABELS:
        # lookbehind negativo: solo inyecta \n si no habia ya uno
        text = re.sub(
            rf"(?<!\n)\s*({re.escape(label)}\s*:)",
            r"\n\1",
            text,
            flags=re.IGNORECASE,
        )

    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


# ---------------------------------------------------------------------------
# Extraccion de bloques del sobre
# ---------------------------------------------------------------------------

def _extract_structural_blocks(body, labels_with_tilde):
    """
    Extrae bloques de texto entre etiquetas estructurales usando posicionamiento.
    Retorna un diccionario {label_lowercase: valor_crudo}.
    """
    positions = []
    for label in labels_with_tilde:
        pattern = rf"(?:^|\n){re.escape(label)}\s*:\s*"
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            positions.append({
                "label": label,
                "start": m.end(),
                "match_start": m.start(),
            })

    positions.sort(key=lambda x: x["match_start"])
    extracted = {label: None for label in labels_with_tilde}

    for i, pos in enumerate(positions):
        end_idx = positions[i + 1]["match_start"] if i + 1 < len(positions) else len(body)
        extracted[pos["label"]] = body[pos["start"]:end_idx].strip()

    return extracted


# ---------------------------------------------------------------------------
# Extraccion dentro de la Descripcion
# ---------------------------------------------------------------------------

def _extract_from_description(descripcion_raw):
    r"""
    Extrae campos estructurados del bloque Descripcion en dos pasos:
      1. Normalizar (inyectar saltos de linea antes de etiquetas internas).
      2. Aplicar regex multiline con ^ para evitar falsos positivos en payload.

    Reglas:
      - IPs: patron estricto [0-9]{1,3}(?:\.[0-9]{1,3}){3}
      - Payload: [\s\S]* sin limite, siempre al final
      - ^ evita capturar srcip=... dentro de msg="Source IP: fake"
    """
    result = {
        "rule_name": None,
        "source_ip": None,
        "destination_ip": None,
        "payload": None,
    }

    if not descripcion_raw:
        return result

    # Paso 1: normalizar para inyectar saltos antes de etiquetas internas
    desc = _normalize_description(descripcion_raw)

    # Rule Name (multiline seguro)
    m = re.search(r"(?m)^Rule Name:\s*(.+)$", desc)
    raw_rule_name = _first(m)
    # Post-proceso: split por " - ", descartar los dos primeros elementos
    # (dominio y severidad), el resto es el nombre real de la regla.
    # Ej: "MASISA - High - CSIRT_Chile_Tivit_Phishing" -> "CSIRT_Chile_Tivit_Phishing"
    if raw_rule_name:
        parts = [p.strip() for p in raw_rule_name.split("-")]
        result["rule_name"] = " - ".join(parts[2:]).strip() if len(parts) > 2 else raw_rule_name
    else:
        result["rule_name"] = None

    # Source IP (patron estricto - evita [.\d]+ demasiado permisivo)
    m = re.search(
        r"(?m)^Source IP:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        desc,
    )
    result["source_ip"] = _first(m)

    # Destination IP
    m = re.search(
        r"(?m)^Destination IP:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        desc,
    )
    result["destination_ip"] = _first(m)

    # Payload: captura TODO lo que sigue - NUNCA truncar - NUNCA parsear
    m = re.search(r"(?m)^Payload:\s*([\s\S]*)", desc)
    if m:
        payload_val = m.group(1).strip()
        result["payload"] = payload_val if payload_val else None

    return result


# ---------------------------------------------------------------------------
# Derivacion de campos
# ---------------------------------------------------------------------------

def _derive_domain_and_severity(rule_name):
    """
    Deriva domain y severity a partir del rule_name.
      domain   -> primer bloque ^[A-Z0-9]+ (soporta numeros)
      severity -> \b(high|medium|low|critical)\b -> UPPER
    """
    domain = "N/A"
    severity = "N/A"

    if not rule_name:
        return domain, severity

    m_domain = re.search(r"^[A-Z0-9]+", rule_name, re.IGNORECASE)
    if m_domain:
        domain = m_domain.group(0).upper()

    m_sev = re.search(r"\b(high|medium|low|critical)\b", rule_name, re.IGNORECASE)
    if m_sev:
        severity = m_sev.group(1).upper()

    return domain, severity


def _extract_ticket_id(text):
    """
    Extrae Ticket ID con word-boundary para evitar capturas parciales.
    Soporta R####, INC####, TKT-####.
    """
    m = re.search(r"\b(R\d+|INC\d+|TKT-\d+)\b", text, re.IGNORECASE)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------

def parse_incident_email(message_details):
    """
    Parsea un correo electronico de incidente SOC.

    Retorna:
        ticket_id, provider, domain, severity, subject,
        requester, category, subcategory, third_level,
        rule_name, source_ip, destination_ip,
        descripcion_full, payload
    """
    try:
        email_subject = message_details.get("subject", "")
        raw_body = message_details.get("body", "") or message_details.get("snippet", "")

        # 1. Normalizar cuerpo (etiquetas del sobre)
        body = _normalize_body(raw_body, STRUCTURAL_LABELS_TILDE)
        text_global = email_subject + "\n" + body

        # 2. Ticket ID (busqueda global con \b para evitar parciales)
        ticket_id = _extract_ticket_id(text_global) or "N/A"

        # 3. Extraccion en bloques del sobre
        blocks = _extract_structural_blocks(body, STRUCTURAL_LABELS_TILDE)

        asunto_raw = blocks.get("Asunto") or email_subject or ""
        descripcion_raw = blocks.get("Descripci\u00f3n") or ""

        # Fallback Categoria
        if not blocks.get("Categor\u00eda"):
            m = re.search(r"Categor[i\u00ed]a:\s*(.+)", text_global, re.IGNORECASE)
            if m:
                blocks["Categor\u00eda"] = m.group(1).strip()

        # 4. Derivar domain/severity desde el Asunto
        domain = "N/A"
        severity = "N/A"
        clean_subject = _clean(asunto_raw)

        m_subj = re.search(
            r"^(\w+)\s*-\s*(HIGH|MEDIUM|LOW|CRITICAL)\s*-\s*(.+)",
            asunto_raw,
            re.IGNORECASE,
        )
        if m_subj:
            domain = m_subj.group(1).strip().upper()
            severity = m_subj.group(2).strip().upper()
            clean_subject = m_subj.group(3).strip()
        else:
            parts = [p.strip() for p in asunto_raw.split("-")]
            if len(parts) >= 3:
                domain = parts[0].upper()
                severity = parts[1].upper()

        # 5. Extraccion dentro del bloque Descripcion
        desc_fields = _extract_from_description(descripcion_raw)

        # Refinar domain/severity con rule_name si Subject no los dio
        if desc_fields["rule_name"]:
            rule_domain, rule_severity = _derive_domain_and_severity(desc_fields["rule_name"])
            if domain == "N/A":
                domain = rule_domain
            if severity == "N/A":
                severity = rule_severity

        # 6. Payload final
        final_payload = desc_fields["payload"] or descripcion_raw or raw_body or "N/A"

        return {
            "ticket_id":      ticket_id,
            "provider":       "SensrIT",
            "domain":         domain,
            "severity":       severity,
            "subject":        clean_subject,
            "requester":      _clean(blocks.get("Solicitante")),
            "category":       _clean(blocks.get("Categor\u00eda")),
            "subcategory":    _clean(blocks.get("Subcategor\u00eda")),
            "third_level":    _clean(blocks.get("Tercer nivel")),
            "rule_name":      desc_fields["rule_name"] or "N/A",
            "source_ip":      desc_fields["source_ip"] or "N/A",
            "destination_ip": desc_fields["destination_ip"] or "N/A",
            "payload":        final_payload,
        }

    except Exception as e:
        logger.error(f"Error en parse_incident_email: {e}", exc_info=True)
        return None
