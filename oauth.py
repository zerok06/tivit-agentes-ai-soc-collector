from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# 📩 Permiso solo lectura
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# 🔐 Cargar credenciales OAuth (descargadas de GCP)
flow = InstalledAppFlow.from_client_secrets_file(
    'credenciales.json',  # <-- tu archivo OAuth
    SCOPES
)

# 🌐 Abre navegador para login
creds = flow.run_local_server(port=8080)

print("✅ ACCESS TOKEN:", creds.token)
print("✅ REFRESH TOKEN:", creds.refresh_token)

# 🔌 Conectar con Gmail API
service = build('gmail', 'v1', credentials=creds)

# 📥 Obtener últimos correos
results = service.users().messages().list(
    userId='me',
    maxResults=5
).execute()

messages = results.get('messages', [])

print("\n📩 Correos encontrados:", len(messages))

for msg in messages:
    msg_detail = service.users().messages().get(
        userId='me',
        id=msg['id']
    ).execute()

    print("\n🧾 ID:", msg['id'])
    print("📌 Snippet:", msg_detail['snippet'])
    print("-" * 50)