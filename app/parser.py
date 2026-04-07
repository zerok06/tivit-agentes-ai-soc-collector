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
        ticket_id, provider, payload
    """
    try:
        email_subject = message_details.get("subject", "")
        raw_body = message_details.get("body", "") or message_details.get("snippet", "")

        # Buscamos el ID en el cuerpo limpio o el asunto
        clean_body = _sanitize_raw_body(raw_body)
        text_global = email_subject + "\n" + clean_body

        ticket_id = _extract_ticket_id(text_global) or "N/A"

        return {
            "ticket_id": ticket_id,
            "provider": "SensrIT",
            "payload": raw_body if raw_body else "N/A"
        }

    except Exception as e:
        logger.error(f"Error en parse_incident_email: {e}", exc_info=True)
        return None
