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
        'scopes': credentials.scopes
    }
    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    if 'credentials' not in session:
        return redirect("/login")

    try:
        creds = google.oauth2.credentials.Credentials(**session['credentials'])
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        return f"<h2>Welcome, {profile['emailAddress']}!</h2>"
    except Exception as e:
        return f"<h3>Error accessing Gmail API: {str(e)}</h3>", 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
