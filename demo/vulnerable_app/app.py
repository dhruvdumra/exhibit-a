"""Intentionally vulnerable Flask app for ExhibitA demos. DO NOT DEPLOY.

Each planted bug is provable end-to-end: a crafted request makes something that
should be unreachable show up in the response. The verifier proves exploitability
by observation, not by trusting the model.

  SQL injection        GET  /api/notes?owner=      leaks a secret DB row
  command injection    GET  /api/hello?name=       leaks a process env value
  path traversal       GET  /api/read?file=        reads a file outside content/
  template injection   GET  /api/greet?name=       evaluates a server-side expression
  reflected XSS        GET  /api/search?q=          reflects markup unescaped
  XXE                  POST /api/xml                expands an external entity
"""

import hashlib
import os
import sqlite3
import subprocess

from flask import Flask, Response, jsonify, render_template_string, request
from lxml import etree

app = Flask(__name__)

HERE = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.join(HERE, "content")

# Injected per run by the verifier; leaking it over HTTP proves a vulnerability.
CANARY = os.environ.get("EXHIBITA_CANARY", "EXHIBITA_FLAG_DEV")


def db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    conn.executemany(
        "INSERT INTO notes (owner, body) VALUES (?, ?)",
        [
            ("alice", "Buy milk"),
            ("bob", "Ship the release"),
            ("system", f"internal-canary::{CANARY}"),  # an ordinary user must never see this
        ],
    )
    return conn


@app.route("/api/notes")
def notes():
    owner = request.args.get("owner", "alice")
    conn = db()
    # BUG (SQL injection): user input formatted straight into the query.
    query = "SELECT owner, body FROM notes WHERE owner = '%s'" % owner
    rows = conn.execute(query).fetchall()
    return jsonify([{"owner": o, "body": b} for o, b in rows])


@app.route("/api/hello")
def hello():
    name = request.args.get("name", "world")
    # BUG (command injection): user input concatenated into a shell command.
    greeting = subprocess.getoutput("echo Hello, " + name)
    return jsonify({"greeting": greeting})


@app.route("/api/read")
def read_file():
    name = request.args.get("file", "public.txt")
    # BUG (path traversal): the filename is joined without containment checks.
    with open(os.path.join(CONTENT_DIR, name), encoding="utf-8", errors="replace") as fh:
        return Response(fh.read(), mimetype="text/plain")


@app.route("/api/greet")
def greet():
    name = request.args.get("name", "friend")
    # BUG (template injection): user input concatenated into a template source.
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/api/search")
def search():
    q = request.args.get("q", "")
    # BUG (reflected XSS): user input returned as HTML without escaping.
    return Response("<p>Results for " + q + "</p>", mimetype="text/html")


@app.route("/api/xml", methods=["POST"])
def parse_xml():
    body = request.get_data()
    # BUG (XXE): the parser resolves external entities from untrusted XML.
    parser = etree.XMLParser(resolve_entities=True, no_network=True)
    root = etree.fromstring(body, parser)
    return Response((root.text or "").strip(), mimetype="text/plain")


@app.route("/api/avatar")
def avatar():
    # Likely false positive: MD5 here is only a cache key, not a security control.
    name = request.args.get("name", "")
    return jsonify({"etag": hashlib.md5(name.encode()).hexdigest()})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # BUG: debug=True exposes the interactive debugger (RCE) in production.
    app.run(host="0.0.0.0", port=8000, debug=True)
