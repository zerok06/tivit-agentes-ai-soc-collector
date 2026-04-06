"""
test_parser.py — Prueba local del parser con el email de ejemplo real.
Ejecutar desde la raíz del proyecto:
    python test_parser.py
"""

import sys, json, textwrap

# Simula el entorno sin necesidad de conexión a Gmail ni DB
sys.path.insert(0, ".")

# Patch mínimo de logger para que no arranque handlers de archivo
import logging
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

from app.parser import parse_incident_email

# ── Email de ejemplo (cuerpo real) ────────────────────────────────────────────
SUBJECT = "Se ha creado el ticket R176179"

BODY = """\
Asunto: MASISA - High - CSIRT_Chile_Tivit_Phishing Fired

Solicitante: MASISA SIEM

Categoría: 183 - Solicitud Ciberseguridad

Subcategoría: 865 - SIEM

Tercer nivel: 4180 - Evento

Descripción: AVISO: Mensagem Externa. ADVERTENCIA: Mensaje Externo. The QRadar event custom rule engine sent an automated response: Mar 30, 2026 6:10:30 AM CLST Rule Name: MASISA - High - CSIRT_Chile_Tivit_Phishing Rule Description: MASISA -High - CSIRT_Chile_Tivit_Phishing Indicadores de compromiso CSIRT - Csirt_Chile_Tivit_Phishing ############################################################# Se debe informar vía correo a: - Area Ciberseguridad TIVIT - OPE CL - CIBERSEGURIDAD - Copia Cliente: ricardo.gonzalez@masisa.com ############################################################# Sugerencias: - Se debe realizar bloqueo en Firewall Perimetral de URL o IP maliciosa. - Se debe aislar equipo de la red. - Se debe realizar un analisis completo con solución AV/EDR - Revisar los programas instalados, los procesos en ejecución, y los servicios que se inician con el sistema. - Elimina cualquier software sospechoso o desconocido. - Comenzar con un proceso de Concientización a los usuarios. Source IP: 10.95.21.94 Source Port: 38856 Source Username (from event): N/A Source Network: Masisa.Tableros_Cabrero.Usuarios_Visitas Destination IP: 99.84.160.69 Destination Port: 443 Destination Username (from Account Name): N/A Destination Network: other Protocol: tcp_ip QID: 20268826 Event Name: Amazon.Video - This indicates an attempt to access Amazon Video Event Description: This indicates an attempt to access Amazon Video. Amazon Video is an online video streaming service, formerly Amazon Instant Video and Amazon Unbox. It offers TV series and movies for rental or purchase. It has struck deals with various content provider for exclusive content and also non-exclusive ones like HBO. Category: Notice Log Source ID: 5130 Log Source Name: FortiGate @ 172.29.41.254 Payload: <190>date=2026-03-30 time=06:10:30 devname="FW_FTG_CLU_B_ALI_ACT" devid="FG10E0TB23900294" eventtime=1774861829811581709 tz="-0300" logid="1059028704" type="utm" subtype="app-ctrl" eventtype="signature" level="information" vd="MASISA_ALI" appid=28046 srcip=10.95.21.94 srccountry="Reserved" dstip=99.84.160.69 dstcountry="United States" srcport=38856 dstport=443 srcintf="MASISA_INTX_WAN" srcintfrole="lan" dstintf="MASISA_INTERNET" dstintfrole="dmz" proto=6 service="SSL" direction="outgoing" policyid=192 poluuid="ee345da6-2780-51ee-8165-f75dffea5f16" policytype="policy" sessionid=751448591 applist="Blockeo-Nav-General" action="pass" appcat="Video/Audio" app="Amazon.Video" hostname="s0s7.api.amazonvideo.com" incidentserialno=341221556 url="/" msg="Video/Audio: Amazon.Video" apprisk="elevated" scertcname="t300.api.cer.amazonvideo.com"
"""

message_details = {
    "subject": SUBJECT,
    "body":    BODY,
    "snippet": "",
}

result = parse_incident_email(message_details)

print("\n" + "=" * 60)
print("RESULTADO DEL PARSER")
print("=" * 60)
print(json.dumps(result, indent=2, ensure_ascii=False))

# ── Aserciones ────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("VALIDACIONES")
print("=" * 60)

checks = [
    ("ticket_id",       "R176179"),
    ("domain",          "MASISA"),
    ("severity",        "HIGH"),
    ("source_ip",       "10.95.21.94"),
    ("destination_ip",  "99.84.160.69"),
    # rule_name: "MASISA - High - CSIRT_Chile_Tivit_Phishing"
    #   split("-") -> ["MASISA ", " High ", " CSIRT_Chile_Tivit_Phishing"]
    #   drop 0 y 1 -> "CSIRT_Chile_Tivit_Phishing"
    ("rule_name",       "CSIRT_Chile_Tivit_Phishing"),
]

all_ok = True
for field, expected in checks:
    actual = result.get(field, "")
    ok = actual == expected
    status = "✓ OK" if ok else f"✗ FAIL (esperado: {expected!r}, obtenido: {actual!r})"
    print(f"  {field:20s} → {status}")
    if not ok:
        all_ok = False

# Verificar que el payload contiene el log FortiGate completo
payload_ok = result.get("payload", "").startswith("<190>")
print(f"  {'payload_starts_with_<190>':20s} → {'✓ OK' if payload_ok else '✗ FAIL'}")

print("\n" + ("✅ Todas las validaciones pasaron." if all_ok and payload_ok else "⚠️  Hay fallos que revisar."))
