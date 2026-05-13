import json
import os
import time
from pathlib import Path
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

AWS_REGION = os.getenv("AWS_REGION", "eu-north-1")
LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "cloudtrap-logs")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))

LOG_FILES = {
    "api-service": Path(os.getenv("API_LOG_FILE", "/app/logs/api-service/logs.jsonl")),
    "s3-service": Path(os.getenv("S3_LOG_FILE", "/app/logs/s3-service/logs.jsonl")),
    "login-portal": Path(os.getenv("LOGIN_LOG_FILE", "/app/logs/login-portal/logs.jsonl")),
}

positions = {}


def client():
    return boto3.client("logs", region_name=AWS_REGION)


def ensure_group_and_stream(cw, stream_name):
    try:
        cw.create_log_group(logGroupName=LOG_GROUP)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise

    try:
        cw.create_log_stream(logGroupName=LOG_GROUP, logStreamName=stream_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise


def get_sequence_token(cw, stream_name):
    response = cw.describe_log_streams(
        logGroupName=LOG_GROUP,
        logStreamNamePrefix=stream_name
    )

    for stream in response.get("logStreams", []):
        if stream["logStreamName"] == stream_name:
            return stream.get("uploadSequenceToken")

    return None


def read_new_lines(path):
    if not path.exists():
        return []

    last_pos = positions.get(str(path), 0)

    with path.open("r", encoding="utf-8") as f:
        f.seek(last_pos)
        lines = f.readlines()
        positions[str(path)] = f.tell()

    return lines


def send_events(cw, stream_name, lines):
    events = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
            ts_raw = data.get("timestamp")
            if ts_raw:
                timestamp_ms = int(datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp() * 1000)
            else:
                timestamp_ms = int(time.time() * 1000)
        except Exception:
            timestamp_ms = int(time.time() * 1000)

        events.append({
            "timestamp": timestamp_ms,
            "message": line
        })

    if not events:
        return 0

    events.sort(key=lambda x: x["timestamp"])

    token = get_sequence_token(cw, stream_name)

    kwargs = {
        "logGroupName": LOG_GROUP,
        "logStreamName": stream_name,
        "logEvents": events
    }

    if token:
        kwargs["sequenceToken"] = token

    try:
        cw.put_log_events(**kwargs)
        return len(events)
    except ClientError as e:
        print(f"[!] Failed sending to {stream_name}: {e}", flush=True)
        return 0


def run():
    print(f"[+] CloudTrap forwarder started: local JSONL → CloudWatch", flush=True)
    print(f"[+] region={AWS_REGION}, group={LOG_GROUP}, interval={POLL_INTERVAL}s", flush=True)

    cw = client()

    for stream_name in LOG_FILES:
        ensure_group_and_stream(cw, stream_name)

    while True:
        total = 0

        for stream_name, path in LOG_FILES.items():
            lines = read_new_lines(path)
            if lines:
                count = send_events(cw, stream_name, lines)
                total += count

        if total:
            print(f"[+] Sent {total} events to CloudWatch at {datetime.now(timezone.utc).isoformat()}", flush=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()