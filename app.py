# File: app.py
import os
import base64
from flask import Flask, redirect, request, session, jsonify
from flask_cors import CORS
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.oauth2.credentials
from email.mime.text import MIMEText

from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "REPLACE_WITH_RANDOM_SECRET")

# Session and CORS configuration
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True
Session(app)

CORS(
    app,
    supports_credentials=True,
    origins=["https://fe-gmail-login-kde3.vercel.app"]
)

# Google OAuth configuration
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

# in app.py
import os, requests
from flask import Flask, request, jsonify

ASSEMBLY_KEY = os.getenv("ASSEMBLYAI_API_KEY")

@app.route("/transcribe", methods=["POST"])
def transcribe():
    audio = request.files["audio"]  # assume front-end posts a WebM blob
    # 1) upload
    upload = requests.post(
        "https://api.assemblyai.com/v2/upload",
        headers={"authorization": ASSEMBLY_KEY},
        data=audio.read()
    )
    upload_url = upload.text
    # 2) kick off transcript
    resp = requests.post(
        "https://api.assemblyai.com/v2/transcript",
        headers={
          "authorization": ASSEMBLY_KEY,
          "content-type": "application/json"
        },
        json={"audio_url": upload_url}
    ).json()
    tid = resp["id"]
    # 3) poll until done
    while True:
        status = requests.get(
            f"https://api.assemblyai.com/v2/transcript/{tid}",
            headers={"authorization": ASSEMBLY_KEY}
        ).json()
        if status["status"] == "completed":
            return jsonify({"text": status["text"]})
        if status["status"] == "error":
            return jsonify({"error": "transcription failed"}), 500


@app.route("/unread_ids")
def unread_ids():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(
        userId="me", labelIds=["INBOX", "UNREAD"]
    ).execute()
    messages = results.get("messages", [])
    ids = [m["id"] for m in messages]
    return jsonify({"ids": ids})


@app.route("/latest_email")
def latest_email():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    # If a specific msg_id is provided, use it; otherwise fetch the newest unread
    msg_id = request.args.get("msg_id")
    if not msg_id:
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

    # ─── Extract subject ──────────────────────────────────────────────────────
    subject = next(
        (h["value"] for h in msg["payload"]["headers"] if h["name"] == "Subject"),
        "No Subject"
    )

    # ─── Extract body_html (try text/html first, then text/plain) ────────────
    payload = msg["payload"]
    parts = payload.get("parts", [])

    body_html = ""
    body_text = ""

    if parts:
        # 1) Look for a text/html part
        for part in parts:
            if part.get("mimeType") == "text/html" and part.get("body", {}).get("data"):
                raw_data = part["body"]["data"]
                body_html = base64.urlsafe_b64decode(raw_data).decode("utf-8")
                break
        # 2) If no HTML, look for text/plain
        if not body_html:
            for part in parts:
                if part.get("mimeType") == "text/plain" and part.get("body", {}).get("data"):
                    raw_data = part["body"]["data"]
                    body_text = base64.urlsafe_b64decode(raw_data).decode("utf-8")
                    break
        # 3) If neither part was found, use snippet
        if not body_html and not body_text:
            body_text = msg.get("snippet", "")
    else:
        # Single‐part message (no parts array)
        single_mime = payload.get("mimeType", "")
        single_data = payload.get("body", {}).get("data")
        if single_mime == "text/html" and single_data:
            body_html = base64.urlsafe_b64decode(single_data).decode("utf-8")
        elif single_mime == "text/plain" and single_data:
            body_text = base64.urlsafe_b64decode(single_data).decode("utf-8")
        else:
            body_text = msg.get("snippet", "")

    # 4) If we only have plain‐text, escape HTML and convert newlines to <br>
    if not body_html and body_text:
        safe = (
            body_text.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
        )
        body_html = safe.replace("\n", "<br>")

    # ─── Generate summary (unchanged) ────────────────────────────────────────
    prompt_text = f"""
Summarize the following email in exactly two lines, focusing on the key details:

\"\"\"
{body_text if body_text else ''}
{body_html if body_html else ''}
\"\"\"
"""
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt_text}],
            max_tokens=60
        )
        summary = response.choices[0].message.content.strip()
    except Exception as e:
        summary = "Error generating summary: " + str(e)

    return jsonify({
        "msg_id": msg_id,
        "subject": subject,
        "body_html": body_html,
        "body_text": body_text,
        "summary": summary
    })


import requests
from flask import Response, jsonify

# configure these in your Render environment
ELEVEN_API_KEY = os.getenv("ELEVEN_LABS_API_KEY")
VOICE_ID       = os.getenv("ELEVEN_LABS_VOICE_ID")  # e.g. "EXAVITQu4vr4xnSDxMaL"

@app.route("/tts", methods=["POST"])
def tts():
    payload = request.get_json(force=True)
    text = payload.get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    eleven_resp = requests.post(
        f"https://api.elevenlabs.io/v1/text-to-speech/{VOICE_ID}",
        headers={
          "xi-api-key": ELEVEN_API_KEY,
          "Content-Type": "application/json"
        },
        json={
          "text": text,
          "voice_settings": {"stability": 0.75, "similarity_boost": 0.75}
        }
    )

    if eleven_resp.status_code != 200:
        return jsonify({
          "error": "ElevenLabs TTS failed",
          "details": eleven_resp.text
        }), 502

    # stream back the MPEG audio
    return Response(eleven_resp.content, mimetype="audio/mpeg")


@app.route("/send_reply", methods=["POST"])
def send_reply():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json()
    user_instruction = data.get("reply", "").strip()
    msg_id = data.get("msg_id", "").strip()
    if not user_instruction:
        return jsonify({"error": "No instruction provided"}), 400
    if not msg_id:
        return jsonify({"error": "No msg_id provided"}), 400

    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    try:
        msg = service.users().messages().get(
            userId="me", id=msg_id, format="full"
        ).execute()
    except Exception:
        return jsonify({"error": "Could not fetch that message"}), 400

    original_subject = next(
        (h["value"] for h in msg["payload"]["headers"] if h["name"] == "Subject"),
        "No Subject"
    )

    payload = msg["payload"]
    parts = payload.get("parts", [])
    if parts:
        original_body = ""
        for part in parts:
            if part.get("mimeType") == "text/plain" and part.get("body", {}).get("data"):
                original_body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                break
        if not original_body:
            original_body = msg.get("snippet", "")
    else:
        original_body = (
            base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")
            if payload.get("body", {}).get("data")
            else msg.get("snippet", "")
        )

    prompt_text = f"""
You are a courteous, professional email assistant.
The original email had this subject: "{original_subject}"
and this body:
\"\"\"
{original_body}
\"\"\"

The user’s instruction for their reply is: "{user_instruction}".

Please draft a well-formatted email reply that:
1) Responds appropriately to the original email. you already know the sender's name so address them according to tone of email.
2) Uses the instruction given by the user above. like if user ends with best aanvi, the regards at the end should be Best, next line, Aanvi...
3) Is polite and professional, ready to be sent as-is. keep it short. 
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt_text}]
        )
        formatted_reply = response.choices[0].message.content.strip()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"formatted_reply": formatted_reply})


@app.route("/send_email", methods=["POST"])
def send_email():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json()
    final_reply = data.get("reply_text", "").strip()
    msg_id = data.get("msg_id", "").strip()
    if not final_reply:
        return jsonify({"error": "No reply text provided"}), 400
    if not msg_id:
        return jsonify({"error": "No msg_id provided"}), 400

    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    try:
        msg = service.users().messages().get(userId="me", id=msg_id, format="metadata").execute()
    except Exception:
        return jsonify({"error": "Could not fetch that message"}), 400

    thread_id = msg["threadId"]
    sender = next((h["value"] for h in msg["payload"]["headers"] if h["name"] == "From"), "")

    mime_message = MIMEText(final_reply)
    mime_message["To"] = sender
    mime_message["Subject"] = "Re: " + next(
        (h["value"] for h in msg["payload"]["headers"] if h["name"] == "Subject"), ""
    )
    raw = base64.urlsafe_b64encode(mime_message.as_bytes()).decode("utf-8")

    try:
        service.users().messages().send(
            userId="me",
            body={"raw": raw, "threadId": thread_id}
        ).execute()
        return jsonify({"status": "sent"})
    except Exception as e:
        return jsonify({"error": f"Gmail send failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
