"""Deliberately vulnerable demo app. Do not deploy.

It gives the Semgrep rules and the dependency audit something real to find.
"""
import sqlite3
from urllib.parse import urlsplit

import jwt
import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

# Hosts that outbound webhook callbacks may target.
ALLOWED_CALLBACK_HOSTS = {"hooks.example.com"}


def validate_url(url):
    """Allow only https URLs to allowlisted hosts (SSRF guard).

    The flask-ssrf-requests Semgrep rule treats this function as a sanitizer.
    """
    parts = urlsplit(url or "")
    if parts.scheme != "https" or parts.hostname not in ALLOWED_CALLBACK_HOSTS:
        raise ValueError("callback URL not allowed")
    if parts.username or parts.password or parts.port not in (None, 443):
        raise ValueError("callback URL not allowed")
    return url


@app.route("/preview")
def preview():
    # SSRF: fetches any URL the caller supplies
    return requests.get(request.args.get("url"), timeout=5).text


@app.route("/search")
def search():
    term = request.args.get("q")
    cur = sqlite3.connect("demo.db").cursor()
    # SQL injection: user input in the query string
    cur.execute(f"SELECT title FROM docs WHERE title LIKE '%{term}%'")
    return {"results": cur.fetchall()}


@app.route("/import", methods=["POST"])
def import_config():
    # Insecure deserialization
    return {"loaded": str(yaml.load(request.data))}


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    # Auth bypass: token signature never checked
    claims = jwt.decode(token, options={"verify_signature": False})
    return {"user": claims.get("sub")}


@app.route("/webhook/test", methods=["POST"])
def test_webhook():
    # Callback URL is restricted to allowlisted hosts; no redirects to escape it.
    callback = validate_url(request.form["callback_url"])
    resp = requests.post(
        callback, json={"ping": True}, timeout=5, allow_redirects=False
    )
    return {"status": resp.status_code}
