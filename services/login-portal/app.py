"""
CloudTrap — Login Portal Honeypot
Mimics a corporate login page to capture credential stuffing,
brute force attempts, and phishing tool reuse.
Runs on port 5002.
"""

import json
import os
import logging
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, Response

app = Flask(__name__)

LOG_FILE = Path(os.getenv("LOG_FILE", "logs.jsonl"))

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

HEADER_BLOCKLIST = {"Cookie", "Accept-Encoding"}

# Fake portal HTML — looks like a real corporate login page
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Acme Corp — Sign In</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f0f2f5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.1);
      padding: 40px;
      width: 360px;
    }
    .logo { font-size: 22px; font-weight: 700; color: #1a73e8; margin-bottom: 8px; }
    .subtitle { font-size: 14px; color: #666; margin-bottom: 28px; }
    label { font-size: 13px; color: #333; display: block; margin-bottom: 4px; }
    input {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #ddd;
      border-radius: 6px;
      font-size: 14px;
      margin-bottom: 16px;
      outline: none;
      transition: border-color .2s;
    }
    input:focus { border-color: #1a73e8; }
    button {
      width: 100%;
      padding: 11px;
      background: #1a73e8;
      color: #fff;
      border: none;
      border-radius: 6px;
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
    }
    button:hover { background: #1558b0; }
    .error {
      background: #fce8e6;
      color: #c5221f;
      border-radius: 6px;
      padding: 10px 12px;
      font-size: 13px;
      margin-bottom: 16px;
      display: none;
    }
    .footer { font-size: 12px; color: #aaa; text-align: center; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">Acme Corp</div>
    <div class="subtitle">Sign in to your account</div>
    <div class="error" id="err">Incorrect username or password.</div>
    <form method="POST" action="/login">
      <label for="username">Username or email</label>
      <input type="text" id="username" name="username" autocomplete="username" required>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>
    <div class="footer">© 2024 Acme Corporation. All rights reserved.</div>
  </div>
</body>
</html>"""

# Same page but with the error div visible — shown after a failed attempt
LOGIN_PAGE_ERROR = LOGIN_PAGE.replace(
    'display: none;',
    'display: block;'
)


# ── Helpers ────────────────────────────────────────────────────────────────────
def filtered_headers():
    return {k: v for k, v in request.headers.items() if k not in HEADER_BLOCKLIST}


def write_log(action: str, extra: dict = None):
    entry = {
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "service":        "login-portal",
        "cloud_provider": os.getenv("CLOUD_PROVIDER", "gcp"),
        "source_ip":      request.headers.get("X-Forwarded-For", request.remote_addr),
        "method":         request.method,
        "path":           request.path,
        "user_agent":     request.headers.get("User-Agent"),
        "headers":        filtered_headers(),
        "action":         action,
    }
    if extra:
        entry.update(extra)

    line = json.dumps(entry, ensure_ascii=False)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line, flush=True)


# ── Routes ─────────────────────────────────────────────────────────────────────

# Health check FIRST — before any catch-all
@app.route("/_internal/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET"])
def show_login():
    """Serve the fake login page — log the visit."""
    write_log("page_visit")
    return Response(LOGIN_PAGE, status=200, mimetype="text/html")


@app.route("/login", methods=["POST"])
def handle_login():
    """
    Capture submitted credentials.
    Always return 'invalid' — never grant access.
    Log the username in plain text but hash the password
    so we're not storing captured secrets as-is.
    """
    import hashlib

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Store a hash of the password, not the plaintext
    # Useful for detecting reused/common passwords without storing real creds
    password_hash = hashlib.sha256(password.encode()).hexdigest() if password else None

    write_log("credential_attempt", {
        "username":        username,
        "password_hash":   password_hash,
        "password_length": len(password),
    })

    # Always reject — show error page to keep attacker trying
    return Response(LOGIN_PAGE_ERROR, status=401, mimetype="text/html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Common path attackers probe after failed logins."""
    write_log("password_reset_probe", {
        "username": request.form.get("email", request.form.get("username", "")),
    })
    return Response(
        "<h3 style='font-family:sans-serif;padding:40px'>Password reset is currently unavailable.</h3>",
        status=503,
        mimetype="text/html",
    )


# Catch remaining paths (scanners probe /admin, /dashboard, /wp-login, etc.)
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def catch_all(path):
    write_log("path_probe")
    return Response(LOGIN_PAGE, status=200, mimetype="text/html")


if __name__ == "__main__":
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5002, debug=False)