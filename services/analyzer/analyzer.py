"""
CloudTrap — Analyzer with PostgreSQL
Reads logs from all honeypot services, classifies events,
scores attackers, and writes results to PostgreSQL.
Runs every 60 seconds inside its Docker container.
"""

import json
import os
import sys
import time
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import execute_values

# ── Log sources ────────────────────────────────────────────────────────────────
LOG_FILES = {
    "api-service":   Path(os.getenv("API_LOG_FILE",   "logs/api-service/logs.jsonl")),
    "s3-service":    Path(os.getenv("S3_LOG_FILE",    "logs/s3-service/logs.jsonl")),
    "login-portal":  Path(os.getenv("LOGIN_LOG_FILE", "logs/login-portal/logs.jsonl")),
}

# ── Severity tiers ─────────────────────────────────────────────────────────────
SEVERITY = {
    "credential_attempt":    "HIGH",
    "brute_force":           "CRITICAL",
    "bucket_enumeration":    "MEDIUM",
    "object_access_attempt": "MEDIUM",
    "object_upload_attempt": "HIGH",
    "object_delete_attempt": "HIGH",
    "api_reconnaissance":    "LOW",
    "api_abuse_attempt":     "MEDIUM",
    "ssh_login_attempt":     "HIGH",
    "ssh_command_execution": "CRITICAL",
    "unknown":               "LOW",
}

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ── Database connection ────────────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=int(os.getenv("POSTGRES_PORT", 5432)),
        dbname=os.getenv("POSTGRES_DB", "cloudtrap"),
        user=os.getenv("POSTGRES_USER", "cloudtrap"),
        password=os.getenv("POSTGRES_PASSWORD", "cloudtrap"),
    )


def init_db(conn):
    """Create tables if they don't exist yet."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          SERIAL PRIMARY KEY,
                timestamp   TIMESTAMPTZ,
                service     TEXT,
                source_ip   TEXT,
                method      TEXT,
                path        TEXT,
                action      TEXT,
                command     TEXT,
                attack_type TEXT,
                severity    TEXT,
                cloud_provider TEXT,
                raw         JSONB,
                inserted_at TIMESTAMPTZ DEFAULT NOW()
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

            -- Index for fast IP lookups and time-range queries
            CREATE INDEX IF NOT EXISTS idx_events_source_ip  ON events (source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events (timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_severity   ON events (severity);
            CREATE INDEX IF NOT EXISTS idx_events_attack_type ON events (attack_type);
        """)
        conn.commit()
    print("[+] Database tables ready.")


# ── Log loading ────────────────────────────────────────────────────────────────
def load_logs(service_name, file_path):
    logs = []
    if not file_path.exists():
        print(f"[!] Log file not found ({service_name}): {file_path}")
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
                print(f"[!] Skipping malformed JSON at {file_path}:{line_num}")
    return logs


# ── Event classification ───────────────────────────────────────────────────────
def classify_event(log):
    service  = log.get("service", "")
    path     = log.get("path", "").lower()
    method   = log.get("method", "").upper()
    action   = log.get("action", "").lower()
    payload  = str(log.get("payload", "")).lower()
    command  = log.get("command", "").lower()
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
            "list_objects":  "bucket_enumeration",
            "list_buckets":  "bucket_enumeration",
            "get_object":    "object_access_attempt",
            "put_object":    "object_upload_attempt",
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


# ── Write events to DB ────────────────────────────────────────────────────────
def insert_events(conn, logs):
    """
    Insert log entries that don't already exist in the DB.
    We use (timestamp, source_ip, service, attack_type) as a natural key
    to avoid duplicates when the analyzer reruns on the same log file.
    """
    if not logs:
        return 0

    rows = []
    for log in logs:
        attack_type, severity = classify_event(log)
        source_ip = log.get("source_ip") or log.get("src_ip") or "unknown"
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
            json.dumps(log),
        ))

    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO events
                (timestamp, service, source_ip, method, path, action,
                 command, attack_type, severity, cloud_provider, raw)
            VALUES %s
            ON CONFLICT DO NOTHING
        """, rows)
        inserted = cur.rowcount
        conn.commit()

    return inserted


# ── Rebuild attacker profiles ──────────────────────────────────────────────────
def rebuild_attacker_profiles(conn):
    """
    Recompute attacker_profiles from the events table.
    Runs as a single SQL upsert for efficiency.
    """
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
                    WHEN 'HIGH'     THEN 3
                    WHEN 'MEDIUM'   THEN 2
                    WHEN 'LOW'      THEN 1
                    ELSE 0 END) AS threat_score,
                -- Pick the highest severity seen for this IP
                (ARRAY['CRITICAL','HIGH','MEDIUM','LOW'])[
                    LEAST(
                        MIN(CASE severity
                            WHEN 'CRITICAL' THEN 1
                            WHEN 'HIGH'     THEN 2
                            WHEN 'MEDIUM'   THEN 3
                            WHEN 'LOW'      THEN 4
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
                event_count  = EXCLUDED.event_count,
                threat_score = EXCLUDED.threat_score,
                top_severity = EXCLUDED.top_severity,
                attack_types = EXCLUDED.attack_types,
                first_seen   = EXCLUDED.first_seen,
                last_seen    = EXCLUDED.last_seen,
                updated_at   = EXCLUDED.updated_at
        """)
        conn.commit()
    print("[+] Attacker profiles updated.")


# ── Main loop ──────────────────────────────────────────────────────────────────
def run():
    print("\n=== CloudTrap Analyzer ===")

    # Wait for Postgres to be ready (container startup race)
    for attempt in range(10):
        try:
            conn = get_db()
            break
        except Exception as e:
            print(f"[!] DB not ready yet ({attempt+1}/10): {e}")
            time.sleep(3)
    else:
        print("[!] Could not connect to database after 10 attempts. Exiting.")
        sys.exit(1)

    init_db(conn)

    while True:
        all_logs = []
        for service, path in LOG_FILES.items():
            loaded = load_logs(service, path)
            print(f"[+] {service}: {len(loaded)} events in log file")
            all_logs.extend(loaded)

        if all_logs:
            inserted = insert_events(conn, all_logs)
            print(f"[+] Inserted {inserted} new events into database")
            rebuild_attacker_profiles(conn)
        else:
            print("[!] No logs found yet — honeypots are waiting for traffic")

        print(f"[~] Sleeping 60s...\n")
        time.sleep(60)


if __name__ == "__main__":
    run()