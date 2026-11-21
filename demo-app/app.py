"""Deliberately vulnerable demo app. Do not deploy.

It gives the Semgrep rules and the dependency audit something real to find.
"""
import sqlite3

import jwt
import requests
import yaml
from flask import Flask, request

app = Flask(__name__)


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
