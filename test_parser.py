"""
test_parser.py - Prueba local del parser con casos reales de emails MIME.
Ejecutar desde la raiz del proyecto:
    python test_parser.py
"""

import sys, json
sys.path.insert(0, ".")

import logging
logging.basicConfig(level=logging.WARNING, stream=sys.stdout)

from app.parser import parse_incident_email, _sanitize_raw_body

# ============================================================
# Caso 1: Email de referencia (texto plano limpio)
# ============================================================
SUBJECT_1 = "Se ha creado el ticket R176179"
BODY_1 = """\
Asunto: MASISA - High - CSIRT_Chile_Tivit_Phishing Fired\r\n\r\nSolicitante: MASISA SIEM\r\n\r\nCategor\u00eda: 183 - Solicitud Ciberseguridad\r\n\r\nSubcategor\u00eda: 865 - SIEM\r\n\r\nTercer nivel: 4180 - Evento\r\n\r\nDescripci\u00f3n: AVISO: Mensagem Externa. ADVERTENCIA: Mensaje Externo. The QRadar event custom rule engine sent an automated response: Mar 30, 2026 6:10:30 AM CLST Rule Name: MASISA - High - CSIRT_Chile_Tivit_Phishing Rule Description: MASISA -High - CSIRT_Chile_Tivit_Phishing Indicadores de compromiso CSIRT - Csirt_Chile_Tivit_Phishing Source IP: 10.95.21.94 Source Port: 38856 Destination IP: 99.84.160.69 Destination Port: 443 Payload: <190>date=2026-03-30 time=06:10:30 devname="FW_FTG_CLU_B_ALI_ACT" srcip=10.95.21.94 dstip=99.84.160.69 msg="Video/Audio: Amazon.Video"
"""

# ============================================================
# Caso 2: Email con Quoted-Printable (soft line breaks y =XX)
# Simula lo que llega de automations de Google Workspace
# ============================================================
SUBJECT_2 = "Se ha creado el ticket R999888"
BODY_2 = (
    "Asunto: EMPRESA - High - TEST_Rule Fired\r\n"
    "Solicitante: SOC=20Team\r\n"           # =20 es espacio en QP
    "Categor=C3=ADa: 100 - Ciberseguridad\r\n"  # =C3=AD = i con tilde
    "Subcategor=C3=ADa: 200 - SIEM\r\n"
    "Tercer nivel: 300 - Evento\r\n"
    "Descripci=C3=B3n: QRadar rule fired.\r\n"   # =C3=B3 = o con tilde
    "Rule Name: EMPRESA - High - TEST_Rule\r\n"
    "Source IP: 192.168.1.10\r\n"
    "Destination IP: 8.8.8.8\r\n"
    "Payload: <187>date=2026-04-07 time=06:00:00 msg=3D\"Test=20Alert\"\r\n"
    # =3D es '=' y =20 es ' ' en QP
)

# ============================================================
# Caso 3: Email HTML puro (sin parte text/plain)
# Simula Gmail con formato HTML activado
# ============================================================
SUBJECT_3 = "Se ha creado el ticket R111222"
BODY_3 = """\
<html><body>
<div><b>Asunto:</b> CORP - MEDIUM - PHISHING_Alert Fired</div>
<div><b>Solicitante:</b> CORP SIEM</div>
<div><b>Categor&iacute;a:</b> 183 - Solicitud Ciberseguridad</div>
<div><b>Subcategor&iacute;a:</b> 865 - SIEM</div>
<div><b>Tercer nivel:</b> 4180 - Evento</div>
<div><b>Descripci&oacute;n:</b> QRadar auto response.
Rule Name: CORP - Medium - PHISHING_Alert
Source IP: 172.16.0.5
Destination IP: 1.2.3.4
Payload: &lt;190&gt;date=2026-04-07 msg=&quot;Phishing attempt detected&quot;
</div>
</body></html>
"""

# ============================================================
# Helpers de validacion
# ============================================================

def run_case(name, subject, body, checks, payload_prefix=None):
    print(f"\n{'='*60}")
    print(f"CASO: {name}")
    print("="*60)

    result = parse_incident_email({"subject": subject, "body": body, "snippet": ""})

    if result is None:
        print("ERROR: parse_incident_email retorno None")
        return False

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print()

    all_ok = True
    for field, expected in checks:
        actual = result.get(field, "")
        ok = actual == expected
        status = "OK" if ok else f"FAIL (esperado: {expected!r}, obtenido: {actual!r})"
        print(f"  {field:22s} -> {status}")
        if not ok:
            all_ok = False

    if payload_prefix:
        p = result.get("payload", "")
        ok = p.startswith(payload_prefix)
        print(f"  {'payload_startswith':22s} -> {'OK' if ok else f'FAIL (empieza con: {p[:40]!r})'}")
        if not ok:
            all_ok = False

    print(f"\n  {'OK - Caso pasado' if all_ok else 'FAIL - Revisar'}")
    return all_ok


# ============================================================
# Ejecutar casos
# ============================================================

results = []

results.append(run_case(
    "Caso 1: CRLF + bloque continuo (email real de referencia)",
    SUBJECT_1, BODY_1,
    [
        ("ticket_id",       "R176179"),
        ("domain",          "MASISA"),
        ("severity",        "HIGH"),
        ("source_ip",        "10.95.21.94"),
        ("destination_ip",   "99.84.160.69"),
        ("rule_name",        "CSIRT_Chile_Tivit_Phishing"),
    ],
    payload_prefix="<190>",
))

results.append(run_case(
    "Caso 2: Quoted-Printable (=XX chars, =20 espacios, =3D igual)",
    SUBJECT_2, BODY_2,
    [
        ("ticket_id",       "R999888"),
        ("domain",          "EMPRESA"),
        ("severity",        "HIGH"),
        ("source_ip",        "192.168.1.10"),
        ("destination_ip",   "8.8.8.8"),
        ("rule_name",        "TEST_Rule"),
    ],
    payload_prefix="<187>",
))

results.append(run_case(
    "Caso 3: HTML puro con entidades HTML",
    SUBJECT_3, BODY_3,
    [
        ("ticket_id",       "R111222"),
        ("domain",          "CORP"),
        ("severity",        "MEDIUM"),
    ],
))

# Resumen
passed = sum(1 for r in results if r)
total  = len(results)
print(f"\n{'='*60}")
print(f"RESUMEN: {passed}/{total} casos pasados")
print("="*60)
sys.exit(0 if passed == total else 1)
