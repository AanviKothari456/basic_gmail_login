# File: app.py

import os
import pathlib
import pickle
from flask import Flask, redirect, request, session, url_for
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
    "https://www.googleapis.com/auth/gmail.send"
]

# Your redirect URI (must match what's in Google Cloud Console)
REDIRECT_URI = "https://basic-gmail-login.onrender.com/oauth2callback"


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Enable HTTP for dev

@app.route("/")
def index():
    return "<a href='/login'>Login with Gmail</a>"

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)

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

    creds = google.oauth2.credentials.Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)
    profile = service.users().getProfile(userId='me').execute()
    return f"<h2>Welcome, {profile['emailAddress']}!</h2>"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
