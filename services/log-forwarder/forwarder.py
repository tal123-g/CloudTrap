"""
CloudTrap — CloudWatch Log Forwarder
Polls CloudWatch Logs and writes entries to the shared JSONL files
that the analyzer watches. Bridges cloud logging to local analysis.
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

AWS_REGION = os.getenv("AWS_REGION", "eu-north-1")
LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "cloudtrap-logs")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))

LOG_STREAMS = {
    "api-service": Path(os.getenv("API_LOG_FILE", "/app/logs/api-service/logs.jsonl")),
    "s3-service": Path(os.getenv("S3_LOG_FILE", "/app/logs/s3-service/logs.jsonl")),
    "login-portal": Path(os.getenv("LOGIN_LOG_FILE", "/app/logs/login-portal/logs.jsonl")),
}

# Track last processed timestamp per stream to avoid duplicates
last_timestamps = {}


def get_client():
    return boto3.client("logs", region_name=AWS_REGION)


def fetch_events(client, stream_name, start_time=None):
    """Fetch log events from a CloudWatch stream since start_time"""
    kwargs = {
        "logGroupName": LOG_GROUP,
        "logStreamName": stream_name,
        "startFromHead": True,
        "limit": 100,
    }
    if start_time:
        kwargs["startTime"] = start_time

    try:
        response = client.get_log_events(**kwargs)
        return response.get("events", [])
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        print(f"[!] CloudWatch error for {stream_name}: {e}", flush=True)
        return []


def process_events(stream_name, events, output_path):
    """Write new events to the local JSONL file"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    new_count = 0
    with output_path.open("a", encoding="utf-8") as f:
        for event in events:
            try:
                # Parse the CloudWatch message (it's JSON stored as string)
                data = json.loads(event["message"])
                
                # Ensure it has required fields
                if "timestamp" not in data:
                    data["timestamp"] = datetime.fromtimestamp(
                        event["timestamp"] / 1000, tz=timezone.utc
                    ).isoformat()
                
                f.write(json.dumps(data, ensure_ascii=False) + "\n")
                new_count += 1
                
                # Update last timestamp
                if stream_name not in last_timestamps or event["timestamp"] > last_timestamps[stream_name]:
                    last_timestamps[stream_name] = event["timestamp"]
                    
            except json.JSONDecodeError:
                # Raw log line, write as-is with metadata
                entry = {
                    "timestamp": datetime.fromtimestamp(
                        event["timestamp"] / 1000, tz=timezone.utc
                    ).isoformat(),
                    "service": stream_name,
                    "raw_message": event["message"],
                }
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                new_count += 1

    return new_count


def run():
    print(f"[+] Log forwarder starting — region={AWS_REGION}, group={LOG_GROUP}", flush=True)
    client = get_client()

    while True:
        total = 0
        for stream_name, output_path in LOG_STREAMS.items():
            start = last_timestamps.get(stream_name)
            events = fetch_events(client, stream_name, start)
            if events:
                count = process_events(stream_name, events, output_path)
                total += count

        if total > 0:
            print(f"[+] Forwarded {total} events to JSONL at {datetime.now(timezone.utc).isoformat()}", flush=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    # Create log directories
    for path in LOG_STREAMS.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    run()
