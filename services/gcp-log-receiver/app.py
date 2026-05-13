from flask import Flask, request, jsonify
import json
import os
from pathlib import Path

app = Flask(__name__)

TOKEN = os.getenv("INGEST_TOKEN", "cloudtrap-demo-token")
LOG_FILE = Path(os.getenv("LOGIN_LOG_FILE", "/app/logs/login-portal/logs.jsonl"))

@app.route("/ingest", methods=["POST"])
def ingest():
    if request.headers.get("X-CloudTrap-Token") != TOKEN:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")

    return jsonify({"status": "ok"}), 200

@app.route("/_internal/health")
def health():
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010)