import json
import os
import time
from pathlib import Path

import requests

LOG_FILE = Path(os.getenv("LOGIN_LOG_FILE", "/app/logs/login-portal/logs.jsonl"))
CENTRAL_INGEST_URL = os.getenv("CENTRAL_INGEST_URL")
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "cloudtrap-demo-token")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))

position = 0

def initialize_position():
    global position
    if LOG_FILE.exists():
        position = LOG_FILE.stat().st_size

def read_new_lines():
    global position

    if not LOG_FILE.exists():
        return []

    with LOG_FILE.open("r", encoding="utf-8") as f:
        f.seek(position)
        lines = f.readlines()
        position = f.tell()

    return lines

def run():
    print("[+] GCP forwarder started: GCP JSONL → AWS dashboard receiver", flush=True)

    initialize_position()

    while True:
        lines = read_new_lines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)

                r = requests.post(
                    CENTRAL_INGEST_URL,
                    json=event,
                    headers={
                        "X-CloudTrap-Token": INGEST_TOKEN
                    },
                    timeout=5
                )

                if r.status_code == 200:
                    print("[+] Sent GCP login event to AWS receiver", flush=True)
                else:
                    print(f"[!] Receiver error: {r.status_code} {r.text}", flush=True)

            except Exception as e:
                print(f"[!] Failed to send event: {e}", flush=True)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()
