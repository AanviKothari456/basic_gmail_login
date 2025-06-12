# File: app.py
import os
import io

import base64
from flask import Flask, redirect, request, session, jsonify
from flask_cors import CORS
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.oauth2.credentials
from email.mime.text import MIMEText
from bs4 import BeautifulSoup
import html2text
import requests
from openai import OpenAI

import html2text

from googleapiclient.discovery import build
import google.oauth2.credentials
from PyPDF2 import PdfReader  # or pdfplumber if you prefer

import html2text
import openai


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
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
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

    

    userinfo = requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        params={"access_token": credentials.token}
    ).json()
    session["user_name"] = userinfo.get("given_name") or userinfo.get("name")

    
    return redirect("https://fe-gmail-login-kde3.vercel.app?logged_in=true")

# trying assembly ai

from flask import Flask, request, jsonify

import time


ASSEMBLY_KEY = os.getenv("ASSEMBLYAI_API_KEY")

@app.route("/transcribe", methods=["POST"])
def transcribe():
    # 1) ensure we got a file
    if "audio" not in request.files:
        return jsonify({"error": "No audio file part"}), 400

    audio_file = request.files["audio"]
    data = audio_file.read()
    if not data:
        return jsonify({"error": "Empty audio file"}), 400

    try:
        # 2) upload
        upload_resp = requests.post(
            "https://api.assemblyai.com/v2/upload",
            headers={"authorization": ASSEMBLY_KEY},
            data=data
        )
        upload_resp.raise_for_status()
        upload_url = upload_resp.json()["upload_url"]

        # 3) kick off transcription
        transcript_resp = requests.post(
            "https://api.assemblyai.com/v2/transcript",
            headers={
                "authorization": ASSEMBLY_KEY,
                "content-type": "application/json"
            },
            json={"audio_url": upload_url}
        )
        transcript_resp.raise_for_status()
        transcript_id = transcript_resp.json().get("id")

        # 4) poll until complete (or error)
        while True:
            status_resp = requests.get(
                f"https://api.assemblyai.com/v2/transcript/{transcript_id}",
                headers={"authorization": ASSEMBLY_KEY}
            )
            status_resp.raise_for_status()
            status_json = status_resp.json()
            if status_json["status"] == "completed":
                return jsonify({"text": status_json["text"]})
            if status_json["status"] == "error":
                return jsonify({"error": status_json.get("error", "Unknown error")}), 500
            time.sleep(1)

    except requests.HTTPError as http_err:
        # catch any HTTP errors from AssemblyAI
        return jsonify({"error": f"AssemblyAI HTTP error: {http_err}"}), 502

    except Exception as e:
        # catch-all for anything else
        return jsonify({"error": f"Server error: {str(e)}"}), 500



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

    msg_id = request.args.get("msg_id")
    only_unread = request.args.get("only_unread", "false").lower() == "true"
    sender = "someone"
    if not msg_id:
        results = service.users().messages().list(
            userId="me", labelIds=["INBOX", "UNREAD"], maxResults=1
        ).execute()
        messages = results.get("messages", [])
        if not messages:
            return jsonify({"message": "No unread emails found."})
        msg_id = messages[0]["id"]

    if only_unread:
        msg_metadata = service.users().messages().get(userId="me", id=msg_id, format="metadata").execute()
        thread_id = msg_metadata["threadId"]

        thread = service.users().threads().get(userId="me", id=thread_id, format="full").execute()
        unread_msgs = [m for m in thread["messages"] if "UNREAD" in m.get("labelIds", [])]

        if not unread_msgs:
            return jsonify({"message": "No unread messages in thread."})

        combined_text = ""
        combined_subjects = []

        for m in unread_msgs:
            combined_text += extract_email_text(m, service) + "\n\n"
            subject = next((h["value"] for h in m["payload"]["headers"] if h["name"] == "Subject"), "")
            if subject: 
                combined_subjects.append(subject)
            if sender == "someone":
                sender = next((h["value"] for h in m["payload"]["headers"] if h["name"] == "From"), "someone")

        subject = combined_subjects[-1] if combined_subjects else "No Subject"
        full_text = combined_text.strip()
        body_html = "<br>".join(full_text.splitlines())
        body_text = full_text

        has_pdf = any(p.get("mimeType") == "application/pdf" for m in unread_msgs for p in m["payload"].get("parts", []))
        has_image = any(p.get("mimeType", "").startswith("image/") for m in unread_msgs for p in m["payload"].get("parts", []))
    else:
        msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()

        subject = next(
            (h["value"] for h in msg["payload"]["headers"] if h["name"] == "Subject"),
            "No Subject"
        )

        sender = next((h["value"] for h in msg["payload"]["headers"] if h["name"] == "From"), "someone")


        payload = msg["payload"]
        parts = payload.get("parts", [])

        body_html = ""
        body_text = ""

        if parts:
            for part in parts:
                if part.get("mimeType") == "text/html" and part.get("body", {}).get("data"):
                    raw_data = part["body"]["data"]
                    body_html = base64.urlsafe_b64decode(raw_data).decode("utf-8")
                    break
            if not body_html:
                for part in parts:
                    if part.get("mimeType") == "text/plain" and part.get("body", {}).get("data"):
                        raw_data = part["body"]["data"]
                        body_text = base64.urlsafe_b64decode(raw_data).decode("utf-8")
                        break
            if not body_html and not body_text:
                body_text = msg.get("snippet", "")
        else:
            single_mime = payload.get("mimeType", "")
            single_data = payload.get("body", {}).get("data")
            if single_mime == "text/html" and single_data:
                body_html = base64.urlsafe_b64decode(single_data).decode("utf-8")
            elif single_mime == "text/plain" and single_data:
                body_text = base64.urlsafe_b64decode(single_data).decode("utf-8")
            else:
                body_text = msg.get("snippet", "")

        if not body_html and body_text:
            safe = (
                body_text.replace("&", "&amp;")
                         .replace("<", "&lt;")
                         .replace(">", "&gt;")
            )
            body_html = safe.replace("\n", "<br>")

        full_text = extract_email_text(msg, service)
        has_pdf = any(p.get("mimeType") == "application/pdf" for p in parts)
        has_image = any(p.get("mimeType", "").startswith("image/") for p in parts)

    # ─── Summarization Prompt Logic ──────────────────────────────────────────
    if has_image and not has_pdf and not full_text.strip():
        prompt_text = (
            "You are an expert email summarizer. This email contains only image attachments which you cannot read; "
            f"infer the content solely from the subject line: “{subject}”."
            "Summarize in exactly two concise sentences otherwise. If no subject say you are unable to infer anything. "
            "Do not invent any details.\n\n"
            f"Subject: {subject}\n\nSummary:"
        )

    elif has_pdf:
        prompt_text = (
            "You are an expert email summarizer. Summarize the following email body and PDF attachment(s) "
            "in exactly two concise sentences—no bullet points or numbering. "
            "Include the main action or request, any critical dates or links.\n\n"
            f"Email + PDF content:\n\"\"\"\n{full_text}\n\"\"\"\n\nSummary:"
        )

    else:
        prompt_text = (
            "You are an expert email summarizer. Summarize the following email in exactly two "
            "concise sentences—no bullet points or numbering. Include the sender (or their role), "
            "the main action or request, and any critical details. DO NOT INCLUDE RE: SUBJECT LINE. "
            "If the email body is empty, try to infer from the subject line. Do not make up details. \n\n"
            f"Email content:\n\"\"\"\n{full_text}\n\"\"\"\n\n"
            f"Subject: {subject}\n\nSummary:"
        )

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
        "sender": sender,
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

    user_name = session.get("user_name", "there")

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
You are a courteous, professional email assistant. You are drafting an email from **{user_name}** back to the original sender.
The original email had this subject: "{original_subject}"
and this body:
\"\"\"
{original_body}
\"\"\"

The user’s instruction for their reply is: "{user_instruction}". You have to draft this into a proper email. 
Address the instruction above as {user_name} would. 
Please draft a well-formatted email reply that is from the user pov:
1) Responds appropriately to the original email. you already know the sender's name so address them according to tone of email at the top.
2) Uses the instruction given by the user above to draft the proper email. 
3) Is polite and professional, ready to be sent as-is. keep it short. DO NOT INCLUDE SUBJECT AT ALL. only body of email. 
4) DO NOT INCLUDE ANYTHING ELSE APART FROM THE EMAIL you drafted , no preamble, formatting hints, separators, or explanations—just the plain email content ready to send.
5) Sign off with Best, {user_name}

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

@app.route("/edit_reply", methods=["POST"])
def edit_reply():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json(force=True)
    msg_id = data.get("msg_id", "").strip()
    original_draft = data.get("original_draft", "").strip()
    edit_instructions = data.get("edit_instructions", "").strip()
    if not msg_id or not original_draft or not edit_instructions:
        return jsonify({"error": "Missing parameters"}), 400

    # rebuild Gmail service
    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    # fetch the original email body (plain-text preferred)
    try:
        msg = service.users().messages().get(
            userId="me", id=msg_id, format="full"
        ).execute()
    except Exception:
        return jsonify({"error": "Could not fetch original message"}), 400

    # extract the original body text
    original_body = ""
    parts = msg["payload"].get("parts", [])
    for p in parts:
        if p.get("mimeType") == "text/plain" and p["body"].get("data"):
            original_body = base64.urlsafe_b64decode(
                p["body"]["data"]
            ).decode("utf-8")
            break
    if not original_body:
        original_body = msg.get("snippet", "")

    # build the edit prompt
    prompt = f"""
You are a courteous, professional email assistant.
The original email said:
\"\"\"
{original_body}
\"\"\"

The assistant drafted this reply:
\"\"\"
{original_draft}
\"\"\"

The user has requested this edit:
\"\"\"
{edit_instructions}
\"\"\"

Please provide a revised reply that incorporates the user's instructions,
maintains the original tone and formatting, and is ready to send.
"""

    # call OpenAI to get the revised draft
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )
        revised = resp.choices[0].message.content.strip()
    except Exception as e:
        return jsonify({"error": f"OpenAI error: {e}"}), 500

    return jsonify({"revised_reply": revised})







def pdf_to_text(pdf_bytes: bytes) -> str:
    """
    Extract embedded text from PDF bytes.
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    chunks = []
    for page in reader.pages:
        text = page.extract_text() or ""
        chunks.append(text)
    full = "\n\n".join(chunks).strip()
    return full or "[No extractable text in PDF]"

def extract_email_text(msg, service) -> str:
    """
    Extracts readable content from a Gmail message object:
    1. Plaintext or HTML body (converted to markdown)
    2. All PDF attachments (converted to text)
    3. Falls back to snippet if nothing else is found
    """

    def decode_body(part):
        if "data" in part.get("body", {}):
            return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="ignore")
        return ""

    texts = []
    payload = msg.get("payload", {})
    parts = payload.get("parts", [])

    # — 1) Plaintext —
    for part in parts:
        if part.get("mimeType") == "text/plain":
            txt = decode_body(part)
            if txt.strip():
                texts.append(txt)
                break

    # — 2) HTML (only if no plain text) —
    if not texts:
        for part in parts:
            if part.get("mimeType") == "text/html":
                raw_html = decode_body(part)
                if raw_html.strip():
                    md = html2text.html2text(raw_html)
                    texts.append(md)
                    break

    # — 3) PDF Attachments (all) —
    for part in parts:
        if (
            part.get("filename") and part.get("mimeType") == "application/pdf"
            and part["body"].get("attachmentId")
        ):
            try:
                att = service.users().messages().attachments().get(
                    userId="me",
                    messageId=msg["id"],
                    id=part["body"]["attachmentId"]
                ).execute()
                pdf_bytes = base64.urlsafe_b64decode(att["data"])
                pdf_text = pdf_to_text(pdf_bytes)
                if pdf_text.strip():
                    texts.append(pdf_text)
            except Exception as e:
                print(f"⚠️ PDF extraction failed: {e}")

    # — 4) Fallback: use snippet —
    if not texts and msg.get("snippet"):
        texts.append(msg["snippet"])

    return "\n\n".join(texts).strip()

@app.route("/attachments_summary")
def attachments_summary():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    msg_id = request.args.get("msg_id", "").strip()
    if not msg_id:
        return jsonify({"error": "No msg_id provided"}), 400

    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    # 1) Fetch the full message
    msg = service.users().messages().get(
        userId="me", id=msg_id, format="full"
    ).execute()

    # 2) Extract all text (body + PDFs)
    full = extract_email_text(msg, service)


    # 3) Summarize with OpenAI
    prompt = (
        "You are an expert assistant. Summarize the following email and its PDF attachments "
        "in two concise sentences, covering key points and any critical details.\n\n"
        f"Full content:\n{full}"
    )
    resp = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=120
    )
    summary = resp.choices[0].message.content.strip()

    return jsonify({"attachment_summary": summary})

@app.route("/unread_threads_summary")
def unread_threads_summary():
    if "credentials" not in session:
        return jsonify({"error": "Not logged in"}), 401

    USE_THREAD_SUMMARY = os.getenv("USE_THREAD_SUMMARY", "true").lower() == "true"

    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    # Step 1: Fetch all unread message IDs
    results = service.users().messages().list(
        userId="me", labelIds=["INBOX", "UNREAD"]
    ).execute()
    unread_msgs = results.get("messages", [])
    if not unread_msgs:
        return jsonify({"message": "No unread emails found."})

    # Step 2: Group unread messages by threadId
    thread_map = {}
    for msg in unread_msgs:
        msg_detail = service.users().messages().get(userId="me", id=msg["id"], format="metadata").execute()
        thread_id = msg_detail.get("threadId")
        thread_map.setdefault(thread_id, []).append(msg["id"])

    summaries = []
    for thread_id, unread_ids in thread_map.items():
        thread = service.users().threads().get(userId="me", id=thread_id, format="full").execute()
        unread_msgs_in_thread = [m for m in thread["messages"] if m["id"] in unread_ids]

        # Skip if none (safety)
        if not unread_msgs_in_thread:
            continue

        # Extract text from unread messages only
        texts = []
        for msg in unread_msgs_in_thread:
            text = extract_email_text(msg, service)
            texts.append(text)

        combined_text = "\n\n".join(texts).strip()
        if not combined_text:
            continue

        prompt = (
            "You are an expert assistant. Summarize the following unread emails "
            "in this Gmail thread in exactly two concise sentences. Highlight the key points, requests, or next steps. "
            "Do not include the subject or headers. Only summarize what’s actually written.\n\n"
            f"Unread messages:\n\"\"\"\n{combined_text}\n\"\"\""
        )

        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=120
            )
            summary = response.choices[0].message.content.strip()
        except Exception as e:
            summary = f"Error generating summary: {e}"

        summaries.append({
            "thread_id": thread_id,
            "unread_msg_ids": unread_ids,
            "summary": summary
        })

    return jsonify({"threads": summaries})


@app.route("/add_to_calendar", methods=["POST"])
def add_to_calendar():
    msg_id = request.json.get("msg_id")
    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    gmail = build("gmail", "v1", credentials=creds)
    calendar = build("calendar", "v3", credentials=creds)

    try:
        msg = gmail.users().messages().get(userId="me", id=msg_id, format="full").execute()
        body = get_message_text(msg).lower()

        # VERY simple date/time guess — replace with GPT or better regex later
        title = "Meeting from Email"
        summary = msg["snippet"]
        start_time = "2025-06-13T15:00:00"  # Placeholder: Friday 3pm
        end_time = "2025-06-13T16:00:00"

        event = {
            "summary": title,
            "description": summary,
            "start": {"dateTime": start_time, "timeZone": "Asia/Kolkata"},
            "end": {"dateTime": end_time, "timeZone": "Asia/Kolkata"},
        }

        calendar.events().insert(calendarId="primary", body=event).execute()
        return jsonify({"status": "event created"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/mark_starred", methods=["POST"])
def mark_starred():
    msg_id = request.json.get("msg_id")
    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    try:
        service.users().messages().modify(
            userId="me",
            id=msg_id,
            body={"addLabelIds": ["STARRED"]}
        ).execute()
        return jsonify({"status": "starred"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete_email", methods=["POST"])
def delete_email():
    msg_id = request.json.get("msg_id")
    creds = google.oauth2.credentials.Credentials(**session["credentials"])
    service = build("gmail", "v1", credentials=creds)

    try:
        service.users().messages().trash(userId="me", id=msg_id).execute()
        return jsonify({"status": "deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def get_message_text(message):
    parts = message["payload"].get("parts", [])
    if parts:
        for part in parts:
            if part["mimeType"] == "text/plain":
                return base64.urlsafe_b64decode(part["body"]["data"]).decode()
    else:
        return base64.urlsafe_b64decode(message["payload"]["body"]["data"]).decode()
    return ""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
