# sample_vulnerable_app.py
# This file intentionally contains vulnerabilities for SAST scanner demo.
# DO NOT use any of these patterns in real code.

import os
import pickle
import random
import hashlib
import sqlite3
from flask import Flask, request, redirect

app = Flask(__name__)

# HARDCODED_SECRET
password = "SuperSecret123!"
api_key = "sk-1234567890abcdef"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# DEBUG_ENABLED
DEBUG = True
app.run(host="0.0.0.0", debug=True)

@app.route("/search")
def search():
    # SQL_INJECTION
    term = request.args.get("q")
    query = "SELECT * FROM users WHERE name = '" + term + "'"
    conn = sqlite3.connect("db.sqlite")
    conn.execute(query)

@app.route("/run")
def run_cmd():
    # COMMAND_INJECTION
    cmd = request.args.get("cmd")
    os.system(cmd)

@app.route("/load")
def load_data():
    # INSECURE_DESERIALIZATION
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)

@app.route("/hash")
def weak_hash():
    # WEAK_CRYPTO
    val = request.args.get("val", "")
    return hashlib.md5(val.encode()).hexdigest()

@app.route("/redir")
def open_redir():
    # OPEN_REDIRECT
    url = request.args.get("url")
    return redirect(url)

def gen_token():
    # INSECURE_RANDOM
    return str(random.randint(100000, 999999))

@app.route("/file")
def read_file():
    # PATH_TRAVERSAL
    filename = request.args.get("name")
    return open(filename).read()