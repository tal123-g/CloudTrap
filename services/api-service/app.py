"""
CloudTrap — API Honeypot Service
Mimics a generic REST API and sends logs to both local logs.jsonl and AWS CloudWatch.
Runs on port 5000.
"""

import json
import os
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from flask import Flask, request, jsonify

app = Flask(__name__)

LOG_FILE = Path(os.getenv("LOG_FILE", "logs.jsonl"))

CLOUDWATCH_ENABLED = os.getenv("CLOUDWATCH_ENABLED", "false").lower() == "true"
AWS_REGION = os.getenv("AWS_REGION", "eu-north-1")
LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "cloudtrap-logs")
LOG_STREAM = os.getenv("CLOUDWATCH_LOG_STREAM", "api-service")

logs_client = boto3.client("logs", region_name=AWS_REGION) if CLOUDWATCH_ENABLED else None

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

HEADER_BLOCKLIST = {"Cookie", "Accept-Encoding"}


def setup_cloudwatch():
    if not CLOUDWATCH_ENABLED:
        return

    try:
        logs_client.create_log_group(logGroupName=LOG_GROUP)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise

    try:
        logs_client.create_log_stream(
            logGroupName=LOG_GROUP,
            logStreamName=LOG_STREAM
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise


def send_to_cloudwatch(entry: dict):
    if not CLOUDWATCH_ENABLED:
        return

    try:
        logs_client.put_log_events(
            logGroupName=LOG_GROUP,
            logStreamName=LOG_STREAM,
            logEvents=[
                {
                    "timestamp": int(time.time() * 1000),
                    "message": json.dumps(entry, ensure_ascii=False),
                }
            ],
        )
    except Exception as e:
        print(f"[CloudWatch error] {e}", flush=True)


def safe_payload():
    payload = request.get_json(silent=True)
    if payload is not None:
        return payload

    raw = request.data.decode("utf-8", errors="replace")
    if raw:
        return raw[:4096]

    form = request.form.to_dict()
    return form if form else None


def filtered_headers():
    return {
        k: v
        for k, v in request.headers.items()
        if k not in HEADER_BLOCKLIST
    }


def write_log(entry: dict):
    line = json.dumps(entry, ensure_ascii=False)

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

    send_to_cloudwatch(entry)

    print(line, flush=True)


def fake_response(path: str):
    path_lower = path.lower()

    if "login" in path_lower or "auth" in path_lower:
        return jsonify({"error": "Invalid credentials"}), 401

    if "admin" in path_lower:
        return jsonify({"error": "Forbidden"}), 403

    if path_lower.startswith("/api"):
        return jsonify({"error": "Unauthorized", "code": 401}), 401

    return jsonify({"message": "Service temporarily unavailable"}), 503


@app.route("/_internal/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route(
    "/",
    defaults={"path": ""},
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
@app.route(
    "/<path:path>",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
def catch_all(path):
    full_path = "/" + path

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "api-service",
        "cloud_provider": os.getenv("CLOUD_PROVIDER", "aws"),
        "source_ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "method": request.method,
        "path": full_path,
        "query_string": request.query_string.decode("utf-8", errors="replace") or None,
        "user_agent": request.headers.get("User-Agent"),
        "headers": filtered_headers(),
        "payload": safe_payload(),
    }

    write_log(log_entry)
    return fake_response(full_path)


if __name__ == "__main__":
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    setup_cloudwatch()
    app.run(host="0.0.0.0", port=5000, debug=False)