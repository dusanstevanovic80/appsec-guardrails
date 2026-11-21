import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    name = request.args.get("name")
    cur = sqlite3.connect("app.db").cursor()
    # ruleid: flask-sqli-string-built-query
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cur.fetchall())


@app.route("/user-safe")
def get_user_safe():
    name = request.args.get("name")
    cur = sqlite3.connect("app.db").cursor()
    # ok: flask-sqli-string-built-query
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cur.fetchall())
