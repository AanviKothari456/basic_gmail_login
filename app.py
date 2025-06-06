# File: app.py
import os
import base64
import requests
from io import BytesIO
from flask import Flask, redirect, request, session, jsonify
from flask_cors import CORS
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.oauth2.credentials
from gtts import gTTS
from email.mime.text import MIMEText

# ─── Flask App Setup ─────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "REPLACE_WITH_RANDOM_SECRET")  # Must come before Session()

app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True

Session(app)
CORS(app, supports_credentials=True, origins=["https://fe-gmail-login-kde3.vercel.app"])

# ─── Google OAuth Config ─────────────────────────────────────
CLIENT_SECRETS_FILE = "credentials.json"
REDIRECT_URI = "https://basic-gmail-login.onrender.com/oauth2callback"
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# ─── Routes ──────────────────────────────────────────────────

@app.route("/")
def index():
    return "<a href='/login'>Login with Gmail</a>"

@app.route("/login")
def login():
    session.clear()
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="false",
        prompt="consent"
    )
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
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
    session["credentials"] = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": list(credentials.scopes),
    }
    return redirect("https://fe-gmail-login-kde3.vercel.app?logged_in=true")

@app.route("/latest_email")
def latest_email():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(
        userId="me", labelIds=["INBOX", "UNREAD"], maxResults=1
    ).execute()
    messages = results.get("messages", [])
    if not messages:
        return jsonify({"message": "No unread emails found."})

    msg_id = messages[0]["id"]
    msg = service.users().messages().get(
        userId="me", id=msg_id, format="full"
    ).execute()
    subject = next(
        (h["value"] for h in msg["payload"]["headers"] if h["name"] == "Subject"),
        "No Subject",
    )

    # Extract body
    payload = msg["payload"]
    parts = payload.get("parts", [])
    if parts:
        body = ""
        for part in parts:
            if part.get("mimeType") == "text/plain" and part.get("body", {}).get("data"):
                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                break
        if not body:
            body = msg.get("snippet", "")
    else:
        body = (
            base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")
            if payload.get("body", {}).get("data")
            else msg.get("snippet", "")
        )

    text_to_read = f"Subject: {subject}. Body: {body}"
    audio_base64 = ""

    # Try ElevenLabs
    try:
        eleven_url = "https://api.elevenlabs.io/v1/text-to-speech/EXAVITQu4vr4xnSDxMaL"
        headers = {
            "xi-api-key": os.getenv("ELEVENLABS_API_KEY"),
            "Content-Type": "application/json",
            "accept": "audio/mpeg",
        }
        payload_json = {
            "text": text_to_read,
            "voice_settings": {"stability": 0.5, "similarity_boost": 0.5},
        }
        response = requests.post(eleven_url, headers=headers, json=payload_json)
        response.raise_for_status()
        audio_base64 = base64.b64encode(response.content).decode("utf-8")
    except Exception:
        # Fallback to gTTS (in-memory)
        try:
            tts = gTTS(text=text_to_read, lang="en")
            bio = BytesIO()
            tts.write_to_fp(bio)
            audio_base64 = base64.b64encode(bio.getvalue()).decode("utf-8")
        except Exception:
            return jsonify({"error": "Both ElevenLabs and Google TTS failed"}), 500

    return jsonify({
        "subject": subject,
        "body": body,
        "audio_base64": audio_base64
    })

@app.route("/send_reply", methods=["POST"])
def send_reply():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json()
    reply_text = data.get("reply", "").strip()
    if not reply_text:
        return jsonify({"error": "No reply provided"}), 400

    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(
        userId="me", labelIds=["INBOX", "UNREAD"], maxResults=1
    ).execute()
    messages = results.get("messages", [])
    if not messages:
        return jsonify({"message": "No email to reply to"}), 400

    msg_id = messages[0]["id"]
    msg = service.users().messages().get(
        userId="me", id=msg_id, format="metadata"
    ).execute()
    thread_id = msg["threadId"]
    sender = next(
        (h["value"] for h in msg["payload"]["headers"] if h["name"] == "From"), ""
    )

    mime_message = MIMEText(reply_text)
    mime_message["To"] = sender
    mime_message["Subject"] = "Re: " + next(
        (h["value"] for h in msg["payload"]["headers"] if h["name"] == "Subject"), ""
    )
    raw = base64.urlsafe_b64encode(mime_message.as_bytes()).decode("utf-8")

    service.users().messages().send(
        userId="me", body={"raw": raw, "threadId": thread_id}
    ).execute()
    return jsonify({"status": "Reply sent!"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
