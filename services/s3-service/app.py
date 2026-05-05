"""
CloudTrap — S3 Honeypot Service
Mimics the AWS S3 REST API to capture bucket enumeration,
object access attempts, and data exfiltration patterns.
Runs on port 5001.
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

# Fake bucket names — appear in list_buckets to encourage deeper probing
FAKE_BUCKETS = [
    "prod-backups-2024",
    "internal-assets",
    "customer-exports",
]


# ── Helpers ────────────────────────────────────────────────────────────────────
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
    return {k: v for k, v in request.headers.items() if k not in HEADER_BLOCKLIST}


def write_log(action: str, extra: dict = None):
    """Build and persist a structured log entry for this request."""
    entry = {
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "service":        "s3-service",
        "cloud_provider": os.getenv("CLOUD_PROVIDER", "aws"),
        "source_ip":      request.headers.get("X-Forwarded-For", request.remote_addr),
        "method":         request.method,
        "path":           request.path,
        "query_string":   request.query_string.decode("utf-8", errors="replace") or None,
        "user_agent":     request.headers.get("User-Agent"),
        "headers":        filtered_headers(),
        "payload":        safe_payload(),
        "action":         action,
    }
    if extra:
        entry.update(extra)

    line = json.dumps(entry, ensure_ascii=False)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line, flush=True)


def s3_error_xml(code: str, message: str, status: int) -> Response:
    """
    Return an S3-style XML error so automated tools (boto3, awscli)
    behave as if this is a real S3 endpoint — keeping attackers engaged longer.
    """
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<Error>"
        f"<Code>{code}</Code>"
        f"<Message>{message}</Message>"
        "<RequestId>CLOUDTRAP000000000001</RequestId>"
        "</Error>"
    )
    return Response(body, status=status, mimetype="application/xml")


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def list_buckets():
    """
    Respond with a plausible-looking bucket list.
    Real S3 returns XML; we mimic that so boto3/awscli parse it correctly.
    """
    write_log("list_buckets")

    # Return fake bucket names to entice the attacker to keep probing
    bucket_entries = "".join(
        f"<Bucket><Name>{b}</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>"
        for b in FAKE_BUCKETS
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<ListAllMyBucketsResult>"
        "<Owner><ID>deadbeefdeadbeef</ID><DisplayName>honeypot</DisplayName></Owner>"
        f"<Buckets>{bucket_entries}</Buckets>"
        "</ListAllMyBucketsResult>"
    )
    return Response(body, status=200, mimetype="application/xml")


@app.route("/<bucket_name>", methods=["GET"])
def list_objects(bucket_name):
    write_log("list_objects", {"bucket_name": bucket_name})

    # Return empty object list — real enough to keep automated tools running
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<ListBucketResult>"
        f"<Name>{bucket_name}</Name>"
        "<Prefix></Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>"
        "</ListBucketResult>"
    )
    return Response(body, status=200, mimetype="application/xml")


@app.route("/<bucket_name>", methods=["DELETE"])
def delete_bucket(bucket_name):
    write_log("delete_bucket", {"bucket_name": bucket_name})
    return s3_error_xml("AccessDenied", "Access Denied", 403)


@app.route("/<bucket_name>/<path:object_key>", methods=["GET"])
def get_object(bucket_name, object_key):
    write_log("get_object", {"bucket_name": bucket_name, "object_key": object_key})
    return s3_error_xml("AccessDenied", "Access Denied", 403)


@app.route("/<bucket_name>/<path:object_key>", methods=["PUT", "POST"])
def put_object(bucket_name, object_key):
    write_log("put_object", {"bucket_name": bucket_name, "object_key": object_key})
    return s3_error_xml("AccessDenied", "Access Denied", 403)


@app.route("/<bucket_name>/<path:object_key>", methods=["DELETE"])
def delete_object(bucket_name, object_key):
    write_log("delete_object", {"bucket_name": bucket_name, "object_key": object_key})
    return s3_error_xml("AccessDenied", "Access Denied", 403)


@app.route("/<bucket_name>/<path:object_key>", methods=["HEAD"])
def head_object(bucket_name, object_key):
    """HEAD is used by attackers to check if objects exist without downloading."""
    write_log("head_object", {"bucket_name": bucket_name, "object_key": object_key})
    return Response(status=403)


# ── Health check ───────────────────────────────────────────────────────────────
@app.route("/_internal/health")
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5001, debug=False)