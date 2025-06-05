# File: app.py

import os
from flask import Flask, redirect, request, session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.oauth2.credentials

app = Flask(__name__)
app.secret_key = "REPLACE_WITH_RANDOM_SECRET"

# OAuth2 client secrets file from Google Cloud Console
CLIENT_SECRETS_FILE = "credentials.json"

# Scopes required for Gmail read + send
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]

# Your redirect URI (must match what's in Google Cloud Console)
REDIRECT_URI = "https://basic-gmail-login.onrender.com/oauth2callback"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Enable HTTP for dev

@app.route("/")
def index():
    return "<a href='/login'>Login with Gmail</a>"

@app.route("/login")
def login():
    session.clear()  # Clear previous session to avoid scope mismatch
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='false',  # prevent old scopes from sneaking in
        prompt='consent'                 # force re-consent with correct scopes
    )
    session['state'] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get('state')
    if not state:
        return "Session state missing. Please try logging in again.", 400

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )
    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        return f"<h3>OAuth failed: {str(e)}</h3>", 400

    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': list(credentials.scopes)
    }
    return redirect("/dashboard")

import base64
import requests

@app.route("/dashboard")
def dashboard():
    if 'credentials' not in session:
        return redirect("/login")

    creds = google.oauth2.credentials.Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)
    profile = service.users().getProfile(userId='me').execute()

    # Fetch latest unread
    results = service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD'], maxResults=1).execute()
    messages = results.get('messages', [])

    if not messages:
        return "<h2>No unread emails found</h2>"

    msg_id = messages[0]['id']
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

    subject = next((h['value'] for h in msg['payload']['headers'] if h['name'] == 'Subject'), "No Subject")

    # Get plain text body
    payload = msg['payload']
    parts = payload.get('parts', [])
    if parts:
        for part in parts:
            if part['mimeType'] == 'text/plain':
                body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                break
    else:
        body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8') if 'data' in payload['body'] else msg.get('snippet', '')


    # 🗣️ Use ElevenLabs to synthesize speech
    eleven_url = "https://api.elevenlabs.io/v1/text-to-speech/EXAVITQu4vr4xnSDxMaL"  # Rachel's voice ID
    headers = {
        "xi-api-key": os.getenv("ELEVENLABS_API_KEY"),
        "Content-Type": "application/json"
    }
    payload = {
        "text": f"Subject: {subject}. Email body: {body}",
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.5
        }
    }
    
    headers["accept"] = "audio/mpeg"
    audio_response = requests.post(eleven_url, headers=headers, json=payload, stream=False)

    audio_base64 = base64.b64encode(audio_response.content).decode('utf-8')

    return f"""
        <h2>Welcome, {profile['emailAddress']}!</h2>
        <h3>Latest Email</h3>
        <p><b>Subject:</b> {subject}</p>
        <p><b>Body:</b><br>{body}</p>
        <audio controls>
            <source src="data:audio/mpeg;base64,{audio_base64}" type="audio/mpeg">
            Your browser does not support the audio element.
        </audio><br><br>

        <button onclick="startRecording()">🎤 Reply with Voice</button>
        <p id="transcript"></p>
        <form method="POST" action="/send_reply">
            <input type="hidden" name="reply" id="replyText">
            <button type="submit">Send Reply</button>
        </form>

        <script>
        const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
        
        if (!SpeechRecognition) {
            alert("Your browser does not support speech recognition. Try Chrome.");
        } else {
            const recognition = new SpeechRecognition();
            recognition.continuous = false;
            recognition.lang = 'en-US';
        
            function startRecording() {
                console.log("🎤 Starting recognition...");
                recognition.start();
            }
        
            recognition.onstart = () => {
                console.log("🎙️ Mic open");
            };
        
            recognition.onerror = (event) => {
                console.error("Speech recognition error:", event.error);
                alert("Mic error: " + event.error);
            };
        
            recognition.onresult = (event) => {
                const transcript = event.results[0][0].transcript;
                console.log("🗣️ You said:", transcript);
                document.getElementById("transcript").innerText = "You said: " + transcript;
                document.getElementById("replyText").value = transcript;
            };
        
            window.startRecording = startRecording;
        }
</script>

    """


@app.route("/send_reply", methods=["POST"])
def send_reply():
    if 'credentials' not in session:
        return redirect("/login")

    reply_text = request.form.get("reply", "").strip()
    creds = google.oauth2.credentials.Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)

    # Fetch latest unread message to reply to
    results = service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD'], maxResults=1).execute()
    messages = results.get('messages', [])

    if not messages:
        return "<p>No email to reply to</p>"

    msg_id = messages[0]['id']
    msg = service.users().messages().get(userId='me', id=msg_id, format='metadata').execute()
    thread_id = msg['threadId']
    sender = next((h['value'] for h in msg['payload']['headers'] if h['name'] == 'From'), "")

    # Create MIME reply
    from email.mime.text import MIMEText
    import base64
    mime_message = MIMEText(reply_text)
    mime_message['To'] = sender
    mime_message['Subject'] = "Re: " + next((h['value'] for h in msg['payload']['headers'] if h['name'] == 'Subject'), "")
    raw = base64.urlsafe_b64encode(mime_message.as_bytes()).decode()

    service.users().messages().send(userId='me', body={'raw': raw, 'threadId': thread_id}).execute()
    return "<h2>Reply sent!</h2><a href='/dashboard'>Back to Dashboard</a>"


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
