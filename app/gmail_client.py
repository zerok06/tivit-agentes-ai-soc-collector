"""
gmail_client.py - Cliente Gmail robusto para emails MIME reales.

Problemas que resuelve sobre la version anterior:
  1. Multipart anidado (multipart/alternative dentro de multipart/mixed)
     -> La version anterior solo iteraba el primer nivel de parts[].
  2. Quoted-Printable (soft line breaks con '=' al final de linea)
     -> La version anterior no decodificaba QP, entregaba texto corrupto.
  3. Emails solo-HTML (sin parte text/plain)
     -> La version anterior retornaba body="" y el parser fallaba.
  4. Charset no-UTF8 (latin-1, windows-1252, etc.)
     -> La version anterior usaba .decode('utf-8') fijo y crasheaba.
  5. Saltos CRLF (\\r\\n)
     -> Quedaban en el texto y rompian los regex de fin de linea ($).
"""

import base64
import json
import quopri
import re
from email import message_from_bytes
from email.header import decode_header, make_header

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from app.config import OAUTH_CREDENTIALS_FILE, GMAIL_REFRESH_TOKEN, SCOPES, GMAIL_QUERY
from app.logger import logger


# ---------------------------------------------------------------------------
# Autenticacion
# ---------------------------------------------------------------------------

def get_gmail_service():
    try:
        if not GMAIL_REFRESH_TOKEN:
            logger.error("GMAIL_REFRESH_TOKEN is empty. Cannot authenticate.")
            return None

        with open(OAUTH_CREDENTIALS_FILE, "r") as f:
            creds_data = json.load(f)

        creds_type = "installed" if "installed" in creds_data else "web"
        client_id     = creds_data[creds_type]["client_id"]
        client_secret = creds_data[creds_type]["client_secret"]
        token_uri     = creds_data[creds_type]["token_uri"]

        creds = Credentials(
            token=None,
            refresh_token=GMAIL_REFRESH_TOKEN,
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=SCOPES,
        )

        return build("gmail", "v1", credentials=creds)

    except Exception as e:
        logger.error(f"Error initializing Gmail service (OAuth): {e}")
        return None


# ---------------------------------------------------------------------------
# Listado de mensajes
# ---------------------------------------------------------------------------

def fetch_messages(service):
    try:
        results = service.users().messages().list(userId="me", q=GMAIL_QUERY).execute()
        return results.get("messages", [])
    except Exception as e:
        logger.error(f"Error listing messages: {e}")
        return []


# ---------------------------------------------------------------------------
# Sanitizacion de texto
# ---------------------------------------------------------------------------

def _strip_html(html_text):
    """
    Elimina etiquetas HTML y decodifica entidades comunes.
    No usa BeautifulSoup para evitar dependencia extra.
    """
    # Reemplazar bloques <style> y <script> completos
    text = re.sub(r"<(style|script)[^>]*>[\s\S]*?</\1>", " ", html_text, flags=re.IGNORECASE)
    # Convertir <br> y <p> en saltos de linea antes de eliminar tags
    text = re.sub(r"<br\s*/?>|</p>|</div>|</tr>", "\n", text, flags=re.IGNORECASE)
    # Eliminar todas las demas etiquetas HTML
    text = re.sub(r"<[^>]+>", "", text)
    # Decodificar entidades HTML basicas
    entities = {
        "&amp;": "&", "&lt;": "<", "&gt;": ">",
        "&quot;": '"', "&#39;": "'", "&nbsp;": " ",
        "&aacute;": "á", "&eacute;": "é", "&iacute;": "í",
        "&oacute;": "ó", "&uacute;": "ú", "&ntilde;": "ñ",
        "&Aacute;": "Á", "&Eacute;": "É", "&Iacute;": "Í",
        "&Oacute;": "Ó", "&Uacute;": "Ú", "&Ntilde;": "Ñ",
    }
    for entity, char in entities.items():
        text = text.replace(entity, char)
    return text


def _decode_bytes(data_bytes, charset=None):
    """
    Decodifica bytes a string intentando el charset indicado y luego
    fallbacks seguros para evitar UnicodeDecodeError en produccion.
    """
    charsets = [c for c in [charset, "utf-8", "latin-1", "windows-1252"] if c]
    for cs in charsets:
        try:
            return data_bytes.decode(cs)
        except (UnicodeDecodeError, LookupError):
            continue
    # Ultimo recurso: ignorar caracteres que no se puedan decodificar
    return data_bytes.decode("utf-8", errors="replace")


def _sanitize_text(text):
    """
    Limpieza final del texto extraido del email:
      - Elimina saltos CRLF -> LF  (rompen regex de fin de linea $)
      - Elimina soft line breaks de Quoted-Printable (= al final de linea)
      - Colapsa multiples espacios en blanco en una sola linea
      - Preserva saltos de linea reales
    """
    if not text:
        return ""
    # CRLF -> LF
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Soft line breaks QP: "=\n" -> "" (continuacion de linea)
    text = re.sub(r"=\n", "", text)
    # Eliminar caracteres de control excepto \n y \t
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Nbsp
    text = text.replace("\xa0", " ")
    return text


# ---------------------------------------------------------------------------
# Extraccion de cuerpo MIME (recursiva)
# ---------------------------------------------------------------------------

def _extract_plain_from_parts(parts, depth=0):
    """
    Recorre el arbol MIME de forma recursiva buscando la mejor parte de texto.

    Prioridad:
      1. text/plain  (preferido siempre)
      2. text/html   (fallback: se limpia)

    Soporta:
      - multipart/alternative
      - multipart/mixed
      - multipart/related
      - Anidamiento arbitrario
    """
    plain_candidate = None
    html_candidate  = None

    for part in parts:
        mime_type = part.get("mimeType", "")
        sub_parts = part.get("parts", [])

        # Parte multipart -> recursion
        if sub_parts:
            result = _extract_plain_from_parts(sub_parts, depth + 1)
            if result:
                # Si encontramos texto plano en profundidad, lo preferimos
                return result
            continue

        # Intentar extraer datos de esta parte
        body_data = part.get("body", {}).get("data")
        if not body_data:
            continue

        raw_bytes = base64.urlsafe_b64decode(body_data)
        charset   = None

        # Detectar charset desde headers de la parte
        for header in part.get("headers", []):
            if header.get("name", "").lower() == "content-type":
                m = re.search(r"charset=[\"']?([^\"';\s]+)", header.get("value", ""), re.IGNORECASE)
                if m:
                    charset = m.group(1)

        # Detectar encoding (quoted-printable, base64)
        content_encoding = ""
        for header in part.get("headers", []):
            if header.get("name", "").lower() == "content-transfer-encoding":
                content_encoding = header.get("value", "").lower().strip()

        if content_encoding == "quoted-printable":
            raw_bytes = quopri.decodestring(raw_bytes)
        # base64 ya fue decodificado por urlsafe_b64decode arriba

        text = _decode_bytes(raw_bytes, charset)

        if mime_type == "text/plain":
            plain_candidate = text
            break  # text/plain encontrado -> no seguir buscando
        elif mime_type == "text/html" and html_candidate is None:
            html_candidate = _strip_html(text)

    if plain_candidate is not None:
        return plain_candidate
    return html_candidate


def _extract_body_from_payload(payload):
    """
    Punto de entrada para extraccion del cuerpo del mensaje Gmail API.
    Maneja tanto el caso simple (sin parts) como multipart.
    """
    # Caso simple: payload directo (sin parts)
    if "parts" not in payload:
        body_data = payload.get("body", {}).get("data")
        if body_data:
            raw_bytes = base64.urlsafe_b64decode(body_data)
            mime_type = payload.get("mimeType", "text/plain")

            # Detectar charset
            charset = None
            for header in payload.get("headers", []):
                if header.get("name", "").lower() == "content-type":
                    m = re.search(r"charset=[\"']?([^\"';\s]+)", header.get("value", ""), re.IGNORECASE)
                    if m:
                        charset = m.group(1)

            text = _decode_bytes(raw_bytes, charset)
            if "html" in mime_type:
                text = _strip_html(text)
            return text
        return ""

    # Caso multipart: recorrer arbol MIME
    return _extract_plain_from_parts(payload.get("parts", [])) or ""


# ---------------------------------------------------------------------------
# Decodificacion de headers (Subject puede venir encoded)
# ---------------------------------------------------------------------------

def _decode_header_value(value):
    """
    Decodifica un header de email que puede venir encoded
    (ej: =?utf-8?B?...?= o =?iso-8859-1?Q?...?=).
    """
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value or ""


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------

def get_message_details(service, msg_id):
    try:
        message = service.users().messages().get(
            userId="me", id=msg_id, format="full"
        ).execute()

        payload = message.get("payload", {})
        headers = payload.get("headers", [])

        subject = ""
        sender  = ""
        for header in headers:
            name = header.get("name", "")
            if name == "Subject":
                subject = _decode_header_value(header.get("value", ""))
            elif name == "From":
                sender = _decode_header_value(header.get("value", ""))

        # Extraccion robusta del cuerpo
        raw_body = _extract_body_from_payload(payload)

        # Sanitizacion final (CRLF, QP soft breaks, caracteres de control)
        clean_body = _sanitize_text(raw_body)

        logger.info(
            f"Message {msg_id}: subject={subject!r}, "
            f"body_len={len(clean_body)}, "
            f"body_preview={clean_body[:80]!r}"
        )

        return {
            "id":      msg_id,
            "subject": subject,
            "sender":  sender,
            "snippet": message.get("snippet", ""),
            "body":    clean_body,
        }

    except Exception as e:
        logger.error(f"Error fetching message details for {msg_id}: {e}", exc_info=True)
        return None
