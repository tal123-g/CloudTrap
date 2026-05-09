"""
CloudTrap — Analyzer with PostgreSQL
Reads logs from all honeypot services, classifies events,
enriches source IPs with geolocation data, scores attackers,
and writes results to PostgreSQL.
Runs every 60 seconds inside its Docker container.
"""

import json
import os
import sys
import time
from pathlib import Path

import psycopg2
import requests
from psycopg2.extras import execute_values

# ── Log sources ────────────────────────────────────────────────────────────────
LOG_FILES = {
    "api-service": Path(os.getenv("API_LOG_FILE", "logs/api-service/logs.jsonl")),
    "s3-service": Path(os.getenv("S3_LOG_FILE", "logs/s3-service/logs.jsonl")),
    "login-portal": Path(os.getenv("LOGIN_LOG_FILE", "logs/login-portal/logs.jsonl")),
}

# ── Severity tiers ─────────────────────────────────────────────────────────────
SEVERITY = {
    "credential_attempt": "HIGH",
    "brute_force": "CRITICAL",
    "bucket_enumeration": "MEDIUM",
    "object_access_attempt": "MEDIUM",
    "object_upload_attempt": "HIGH",
    "object_delete_attempt": "HIGH",
    "api_reconnaissance": "LOW",
    "api_abuse_attempt": "MEDIUM",
    "ssh_login_attempt": "HIGH",
    "ssh_command_execution": "CRITICAL",
    "unknown": "LOW",
}


def get_db():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=int(os.getenv("POSTGRES_PORT", 5432)),
        dbname=os.getenv("POSTGRES_DB", "cloudtrap"),
        user=os.getenv("POSTGRES_USER", "cloudtrap"),
        password=os.getenv("POSTGRES_PASSWORD", "cloudtrap"),
    )


def init_db(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id             SERIAL PRIMARY KEY,
                timestamp      TIMESTAMPTZ,
                service        TEXT,
                source_ip      TEXT,
                method         TEXT,
                path           TEXT,
                action         TEXT,
                command        TEXT,
                attack_type    TEXT,
                severity       TEXT,
                cloud_provider TEXT,
                country        TEXT,
                city           TEXT,
                isp            TEXT,
                latitude       FLOAT,
                longitude      FLOAT,
                raw            JSONB,
                inserted_at    TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS attacker_profiles (
                source_ip    TEXT PRIMARY KEY,
                event_count  INT DEFAULT 0,
                threat_score INT DEFAULT 0,
                top_severity TEXT,
                attack_types TEXT[],
                first_seen   TIMESTAMPTZ,
                last_seen    TIMESTAMPTZ,
                updated_at   TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity);
            CREATE INDEX IF NOT EXISTS idx_events_attack_type ON events (attack_type);
        """)
        conn.commit()
    print("[+] Database tables ready.", flush=True)


def load_logs(service_name, file_path):
    logs = []

    if not file_path.exists():
        print(f"[!] Log file not found ({service_name}): {file_path}", flush=True)
        return logs

    with file_path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                entry = json.loads(line)
                entry.setdefault("service", service_name)
                logs.append(entry)
            except json.JSONDecodeError:
                print(f"[!] Skipping malformed JSON at {file_path}:{line_num}", flush=True)

    return logs


# ── IP Geolocation ─────────────────────────────────────────────────────────────
def get_ip_geolocation(ip):
    """Lookup geolocation for an IP using ip-api.com."""

    if not ip or ip in ("unknown", "127.0.0.1", "::1", "localhost"):
        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "latitude": None,
            "longitude": None,
        }

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
            }

    except Exception as e:
        print(f"[!] Geolocation failed for {ip}: {e}", flush=True)

    return {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "latitude": None,
        "longitude": None,
    }


def classify_event(log):
    service = log.get("service", "")
    path = log.get("path", "").lower()
    method = log.get("method", "").upper()
    action = log.get("action", "").lower()
    payload = str(log.get("payload", "")).lower()
    command = log.get("command", "").lower()
    attempts = log.get("attempts", 0)

    if service == "api-service":
        if "login" in path or "auth" in path or "password" in payload:
            attack = "credential_attempt"
        elif method == "GET":
            attack = "api_reconnaissance"
        elif method in ("POST", "PUT", "PATCH", "DELETE"):
            attack = "api_abuse_attempt"
        else:
            attack = "unknown"

    elif service == "s3-service":
        action_map = {
            "list_objects": "bucket_enumeration",
            "list_buckets": "bucket_enumeration",
            "get_object": "object_access_attempt",
            "put_object": "object_upload_attempt",
            "delete_object": "object_delete_attempt",
            "delete_bucket": "object_delete_attempt",
        }
        attack = action_map.get(action, "api_reconnaissance")

    elif service == "login-portal":
        if action == "credential_attempt":
            attack = "credential_attempt"
        elif action == "brute_force" or int(attempts or 0) > 3:
            attack = "brute_force"
        else:
            attack = "credential_attempt"

    elif service == "ssh-service":
        if command:
            attack = "ssh_command_execution"
        elif int(attempts or 0) > 3:
            attack = "brute_force"
        else:
            attack = "ssh_login_attempt"

    else:
        attack = "unknown"

    return attack, SEVERITY.get(attack, "LOW")


def insert_events(conn, logs):
    if not logs:
        return 0

    rows = []

    for log in logs:
        attack_type, severity = classify_event(log)
        source_ip = log.get("source_ip") or log.get("src_ip") or "unknown"
        geo = get_ip_geolocation(source_ip) or {
            "country": "Unknown", "city": "Unknown",
            "isp": "Unknown", "latitude": None, "longitude": None,
        }

        rows.append((
            log.get("timestamp"),
            log.get("service"),
            source_ip,
            log.get("method"),
            log.get("path"),
            log.get("action"),
            log.get("command"),
            attack_type,
            severity,
            log.get("cloud_provider", "aws"),
            geo["country"],
            geo["city"],
            geo["isp"],
            geo["latitude"],
            geo["longitude"],
            json.dumps(log),
        ))

    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO events
                (timestamp, service, source_ip, method, path, action,
                 command, attack_type, severity, cloud_provider,
                 country, city, isp, latitude, longitude, raw)
            VALUES %s
            ON CONFLICT DO NOTHING
        """, rows)

        inserted = cur.rowcount
        conn.commit()

    return inserted


def rebuild_attacker_profiles(conn):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO attacker_profiles
                (source_ip, event_count, threat_score, top_severity,
                 attack_types, first_seen, last_seen, updated_at)
            SELECT
                source_ip,
                COUNT(*) AS event_count,
                SUM(CASE severity
                    WHEN 'CRITICAL' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0 END) AS threat_score,
                (ARRAY['CRITICAL','HIGH','MEDIUM','LOW'])[
                    LEAST(
                        MIN(CASE severity
                            WHEN 'CRITICAL' THEN 1
                            WHEN 'HIGH' THEN 2
                            WHEN 'MEDIUM' THEN 3
                            WHEN 'LOW' THEN 4
                            ELSE 5 END),
                        4
                    )
                ] AS top_severity,
                ARRAY_AGG(DISTINCT attack_type) AS attack_types,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen,
                NOW() AS updated_at
            FROM events
            GROUP BY source_ip
            ON CONFLICT (source_ip) DO UPDATE SET
                event_count = EXCLUDED.event_count,
                threat_score = EXCLUDED.threat_score,
                top_severity = EXCLUDED.top_severity,
                attack_types = EXCLUDED.attack_types,
                first_seen = EXCLUDED.first_seen,
                last_seen = EXCLUDED.last_seen,
                updated_at = EXCLUDED.updated_at
        """)
        conn.commit()

    print("[+] Attacker profiles updated.", flush=True)


def run():
    print("\n=== CloudTrap Analyzer ===", flush=True)

    for attempt in range(10):
        try:
            conn = get_db()
            break
        except Exception as e:
            print(f"[!] DB not ready yet ({attempt + 1}/10): {e}", flush=True)
            time.sleep(3)
    else:
        print("[!] Could not connect to database after 10 attempts. Exiting.", flush=True)
        sys.exit(1)

    init_db(conn)

    while True:
        all_logs = []

        for service, path in LOG_FILES.items():
            loaded = load_logs(service, path)
            print(f"[+] {service}: {len(loaded)} events in log file", flush=True)
            all_logs.extend(loaded)

        if all_logs:
            inserted = insert_events(conn, all_logs)
            print(f"[+] Inserted {inserted} new events into database", flush=True)
            rebuild_attacker_profiles(conn)
        else:
            print("[!] No logs found yet — honeypots are waiting for traffic", flush=True)

        print("[~] Sleeping 60s...\n", flush=True)
        time.sleep(60)


if __name__ == "__main__":
    run()
