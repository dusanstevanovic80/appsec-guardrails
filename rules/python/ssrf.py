from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: flask-ssrf-requests
    return requests.get(url).text


@app.route("/fetch-safe")
def fetch_safe():
    url = validate_url(request.args.get("url"))
    # ok: flask-ssrf-requests
    return requests.get(url).text


def fetch_static():
    # ok: flask-ssrf-requests
    return requests.get("https://api.example.com/status").text
