# File: app.py
import os
import base64
import requests
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

    # Extract subject
    subject = next(
        (h["value"] for h in msg["payload"]["headers"] if h["name"] == "Subject"),
        "No Subject"
    )

    # Extract plain-text body
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

    # Generate a two-line summary using OpenAI
    prompt_text = f"""
Summarize the following email in exactly two lines, focusing on the key details:

\"\"\"
{body}
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
        "subject": subject,
        "body": body,
        "summary": summary
    })

@app.route("/send_reply", methods=["POST"])
def send_reply():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json()
    user_instruction = data.get("reply", "").strip()
    if not user_instruction:
        return jsonify({"error": "No instruction provided"}), 400

    # Fetch the latest unread email again
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
        userId="me", id=msg_id, format="full"
    ).execute()

    # Extract original subject
    original_subject = next(
        (h["value"] for h in msg["payload"]["headers"] if h["name"] == "Subject"),
        "No Subject"
    )

    # Extract original body
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

    # Build the prompt for OpenAI
    prompt_text = f"""
You are a courteous, professional email assistant.
The original email had this subject: "{original_subject}"
and this body:
\"\"\"
{original_body}
\"\"\"

The user’s instruction for their reply is: "{user_instruction}".

Please draft a well-formatted email reply that:
1) Responds appropriately to the original email.
2) Uses the instruction given by the user above.
3) Keeps the same subject line prefixed with “Re:”.
4) Is polite and professional, ready to be sent as-is.
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
    if not final_reply:
        return jsonify({"error": "No reply text provided"}), 400

    # Re‐fetch the latest unread message to get thread & from-address
    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(
        userId="me", labelIds=["INBOX", "UNREAD"], maxResults=1
    ).execute()
    messages = results.get("messages", [])
    if not messages:
        return jsonify({"message": "No email to reply to"}), 400

    msg_id = messages[0]["id"]
    msg = service.users().messages().get(userId="me", id=msg_id, format="metadata").execute()
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
