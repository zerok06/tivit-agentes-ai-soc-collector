"""
parser.py - Extractor robusto de incidentes SOC desde correo electronico.

Estrategia de tres pasos:
  1. Sanitizar el cuerpo crudo (CRLF, QP, HTML residual, disclaimers)
  2. Normalizar etiquetas del sobre (Asunto, Descripcion, etc.)
  3. Normalizar etiquetas internas de la descripcion (Rule Name, Source IP, etc.)
     => Resuelve el caso real donde el email llega como bloque continuo sin saltos.
  4. Aplicar regex multiline seguras con ^ para evitar falsos positivos en payload.

Tipos de payload soportados:
  - Syslog raw  (<190>date=...)   -> almacenar como string
  - CEF         (CEF:0|...)       -> almacenar como string
  - JSON        ({...})           -> almacenar como string (no parsear)
"""

import re
from app.logger import logger


# ---------------------------------------------------------------------------
# Etiquetas estructurales del sobre del ticket
# ---------------------------------------------------------------------------

# Etiquetas estructurales del sobre.
# Mapa: nombre_canonico -> patron_regex   (acepta tilde o no, Markdown, espacios)
STRUCTURAL_LABEL_MAP = {
    "Asunto":           r"Asunto",
    "Solicitante":      r"Solicitante",
    "Categor\u00eda":   r"Categor[i\u00ed]a",
    "Subcategor\u00eda": r"Subcategor[i\u00ed]a",
    "Tercer nivel":    r"Tercer\s+nivel",
    "Descripci\u00f3n": r"Descripci[o\u00f3]n",
}

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

# Patrones de disclaimer/firma que se eliminan antes de parsear
_DISCLAIMER_PATTERNS = [
    # AVISO externo tipico de Workspace
    r"AVISO:\s*Mensagem\s*Externa\.?",
    r"ADVERTENCIA:\s*Mensaje\s*Externo\.?",
    r"This\s+message\s+(was sent|originated|comes)\s+from\s+outside",
    r"Este\s+correo\s+(fue\s+enviado|proviene|llega)\s+desde\s+fuera",
    # Firmas genericas
    r"--+\s*\n.*?(Confidential|Privado|Aviso Legal)[\s\S]{0,500}",
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


# ---------------------------------------------------------------------------
# Sanitizacion del cuerpo crudo (NUEVO - resuelve el problema MIME/HTML)
# ---------------------------------------------------------------------------

def _decode_html_entities(text):
    """
    Decodifica entidades HTML comunes y numericas.
    Cubre el rango Latin-1 completo y entidades nombradas frecuentes.
    """
    # Entidades numericas decimales: &#160; -> char
    text = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), text)
    # Entidades numericas hex: &#xA0; -> char
    text = re.sub(r"&#x([0-9A-Fa-f]+);", lambda m: chr(int(m.group(1), 16)), text)
    # Entidades nombradas (abarca Latin-1 completo)
    _ENTITIES = {
        "&amp;": "&",   "&lt;": "<",    "&gt;": ">",
        "&quot;": '"',  "&#39;": "'",   "&nbsp;": " ",
        "&aacute;": "á","&eacute;": "é","&iacute;": "í",
        "&oacute;": "ó","&uacute;": "ú","&ntilde;": "ñ",
        "&Aacute;": "Á","&Eacute;": "É","&Iacute;": "Í",
        "&Oacute;": "Ó","&Uacute;": "Ú","&Ntilde;": "Ñ",
        "&uuml;":   "ü","&ouml;":   "ö","&auml;":   "ä",
        "&copy;": "©",  "&reg;": "®",   "&mdash;": "—",
        "&ndash;": "–", "&lsquo;": "'", "&rsquo;": "'",
        "&ldquo;": '"', "&rdquo;": '"', "&hellip;": "…",
    }
    for entity, char in _ENTITIES.items():
        text = text.replace(entity, char)
    return text


def _sanitize_raw_body(text):
    """
    Limpieza profunda del cuerpo del email antes de cualquier parsing.

    Resuelve los problemas reales de emails HTML/MIME de automations:
      1. CRLF (\\r\\n) -> LF     : rompen regex de fin de linea $
      2. Soft line breaks QP     : '=\\n' indica continuacion de linea
      3. HTML residual           : si gmail_client no lo limpio completamente
      4. Unicode spaces          : \\xa0, \\u200b, etc.
      5. Caracteres de control   : corrompen el texto
      6. Quoted-printable chars  : =3D (=), =20 ( ), etc.
    """
    if not text:
        return ""

    # 1. Normalizar saltos de linea
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # 2. Detect if body uses Quoted-Printable encoding.
    # Heuristica: presencia de secuencias =XX multibyte (=C3=, =C2=, etc.)
    # que son tipicas de QP con UTF-8. Excluye syslog/dates que tambien tienen =XX.
    is_qp = bool(re.search(r"=[C-Fc-f][0-9A-Fa-f]=[0-9A-Fa-f]{2}", text))

    # 3. Decodificar QP usando el modulo estandar (maneja multibyte UTF-8 correctamente)
    if is_qp:
        import quopri

        def _decode_qp_safe(chunk):
            """Decodifica un bloque QP usando quopri, con fallback a original."""
            try:
                decoded_bytes = quopri.decodestring(chunk.encode("ascii", errors="replace"))
                return decoded_bytes.decode("utf-8", errors="replace")
            except Exception:
                return chunk

        # Decodificar linea a linea para proteger el payload syslog
        def _decode_qp_line(line):
            stripped = line.lstrip()
            # No decodificar lineas de syslog raw ni la linea del Payload
            if re.match(r"^<\d|^date=\d{4}", stripped, re.IGNORECASE):
                return line
            if re.match(r"Payload\s*:", stripped, re.IGNORECASE):
                return line  # la linea de payload se preserva completa
            return _decode_qp_safe(line)

        text = "\n".join(_decode_qp_line(line) for line in text.split("\n"))

    # 4. Eliminar HTML si existe
    if re.search(r"<[a-zA-Z]", text):
        # Eliminar bloques style/script
        text = re.sub(r"<(style|script)[^>]*>[\s\S]*?</\1>", " ", text, flags=re.IGNORECASE)
        # Etiquetas de formateo INLINE (b, strong, i, em, span) -> solo quitarlas
        # Critico: <b>Asunto:</b> debe quedar como "Asunto:"
        text = re.sub(r"</?(?:b|strong|i|em|u|span|font)[^>]*>", "", text, flags=re.IGNORECASE)
        # Etiquetas de bloque -> convertir en salto de linea
        text = re.sub(r"<(?:br|p|div|tr|td|th|li|h[1-6])\s*/?>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(r"</(?:p|div|tr|td|th|li|h[1-6]|ul|ol|table)>", "\n", text, flags=re.IGNORECASE)
        # Eliminar todas las demas etiquetas residuales
        text = re.sub(r"<[^>]+>", "", text)
        # Decodificar entidades HTML
        text = _decode_html_entities(text)

    # 5. Normalizar unicode spaces y control chars
    text = text.replace("\xa0", " ")
    text = text.replace("\u200b", "")
    text = text.replace("\u200c", "")
    text = text.replace("\u2019", "'")
    text = text.replace("\u201c", '"')
    text = text.replace("\u201d", '"')
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # 6. Colapsar lineas en blanco excesivas
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


# ---------------------------------------------------------------------------
# Normalizacion del sobre y descripcion
# ---------------------------------------------------------------------------

def _normalize_body(text, label_map):
    """
    Fuerza salto de linea antes de cada etiqueta estructural del sobre.
    Cada etiqueta se busca con su patron flexible (acepta tilde o no, Markdown).
    """
    if not text:
        return ""

    text = text.replace("\xa0", " ")

    for canonical, pattern in label_map.items():
        text = re.sub(
            rf"\s*[\*\_]*{pattern}[\*\_]*\s*:",
            "\n" + canonical + ":",
            text,
            flags=re.IGNORECASE,
        )

    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def _normalize_description(text):
    """
    Fuerza salto de linea antes de cada etiqueta interna del bloque Descripcion.

    Critico: resuelve el caso donde la descripcion es un bloque continuo
    (Rule Name: X Source IP: Y Payload: Z todo en una linea).
    El lookbehind negativo evita dobles saltos si ya existian.
    """
    if not text:
        return ""

    for label in DESCRIPTION_INTERNAL_LABELS:
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

def _extract_structural_blocks(body, label_map):
    """
    Extrae bloques de texto entre etiquetas estructurales usando posicionamiento.
    Retorna un diccionario {nombre_canonico: valor_crudo}.

    Despues de _normalize_body el texto ya tiene los nombres canonicos estandarizados,
    por lo que la busqueda es por nombre exacto (case-insensitive).
    """
    positions = []
    for canonical in label_map:
        pattern = rf"(?:^|\n){re.escape(canonical)}\s*:\s*"
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            positions.append({
                "label":       canonical,
                "start":       m.end(),
                "match_start": m.start(),
            })

    positions.sort(key=lambda x: x["match_start"])
    extracted = {canonical: None for canonical in label_map}

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
        "rule_name":      None,
        "source_ip":      None,
        "destination_ip": None,
        "payload":        None,
    }

    if not descripcion_raw:
        return result

    # Paso 1: normalizar para inyectar saltos antes de etiquetas internas
    desc = _normalize_description(descripcion_raw)

    # Rule Name (multiline seguro)
    m = re.search(r"(?m)^Rule Name:\s*(.+)$", desc)
    raw_rule_name = _first(m)

    # Post-proceso: split por "-", descartar primeros dos elementos
    # (dominio y severidad), el resto es el nombre real de la regla.
    # Ej: "MASISA - High - CSIRT_Chile_Tivit_Phishing" -> "CSIRT_Chile_Tivit_Phishing"
    if raw_rule_name:
        parts = [p.strip() for p in raw_rule_name.split("-")]
        result["rule_name"] = " - ".join(parts[2:]).strip() if len(parts) > 2 else raw_rule_name
    else:
        result["rule_name"] = None

    # Source IP (patron estricto)
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

    # Payload: captura TODO lo que sigue - NUNCA truncar - NUNCA parsear como JSON
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
    Deriva domain y severity a partir del rule_name (ya recortado).
    domain   -> primer bloque ^[A-Z0-9]+ (soporta numeros)
    severity -> word-boundary (high|medium|low|critical) -> UPPER
    """
    domain   = "N/A"
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
        rule_name, source_ip, destination_ip, payload
    """
    try:
        email_subject = message_details.get("subject", "")
        raw_body = message_details.get("body", "") or message_details.get("snippet", "")

        # 1. Sanitizar el cuerpo crudo (CRLF, QP, HTML, unicode garbage)
        clean_body = _sanitize_raw_body(raw_body)

        # 2. Normalizar etiquetas del sobre
        body = _normalize_body(clean_body, STRUCTURAL_LABEL_MAP)
        text_global = email_subject + "\n" + body

        # 3. Ticket ID (word-boundary para evitar parciales)
        ticket_id = _extract_ticket_id(text_global) or "N/A"

        # 4. Extraccion en bloques del sobre
        blocks = _extract_structural_blocks(body, STRUCTURAL_LABEL_MAP)

        asunto_raw      = blocks.get("Asunto") or email_subject or ""
        descripcion_raw = blocks.get("Descripci\u00f3n") or ""

        # Fallback Categoria
        if not blocks.get("Categor\u00eda"):
            m = re.search(r"Categor[i\u00ed]a:\s*(.+)", text_global, re.IGNORECASE)
            if m:
                blocks["Categor\u00eda"] = m.group(1).strip()

        # 5. Derivar domain/severity desde el Asunto
        domain   = "N/A"
        severity = "N/A"
        clean_subject = _clean(asunto_raw)

        m_subj = re.search(
            r"^(\w+)\s*-\s*(HIGH|MEDIUM|LOW|CRITICAL)\s*-\s*(.+)",
            asunto_raw,
            re.IGNORECASE,
        )
        if m_subj:
            domain        = m_subj.group(1).strip().upper()
            severity      = m_subj.group(2).strip().upper()
            clean_subject = m_subj.group(3).strip()
        else:
            parts = [p.strip() for p in asunto_raw.split("-")]
            if len(parts) >= 3:
                domain   = parts[0].upper()
                severity = parts[1].upper()

        # 6. Extraccion dentro del bloque Descripcion
        desc_fields = _extract_from_description(descripcion_raw)

        # Refinar domain/severity con rule_name si Subject no los dio
        if desc_fields["rule_name"]:
            rule_domain, rule_severity = _derive_domain_and_severity(desc_fields["rule_name"])
            if domain   == "N/A":
                domain   = rule_domain
            if severity == "N/A":
                severity = rule_severity

        # 7. Payload final
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
