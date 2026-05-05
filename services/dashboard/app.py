"""
CloudTrap — Dashboard Service (PostgreSQL version)
Serves the monitoring dashboard and exposes attack data
via a JSON API backed by PostgreSQL. Runs on port 5003.
"""

import os
import time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from flask import Flask, jsonify, Response, send_from_directory

app = Flask(__name__, static_folder="static")


# ── DB connection ──────────────────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=int(os.getenv("POSTGRES_PORT", 5432)),
        dbname=os.getenv("POSTGRES_DB", "cloudtrap"),
        user=os.getenv("POSTGRES_USER", "cloudtrap"),
        password=os.getenv("POSTGRES_PASSWORD", "cloudtrap"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


# ── API routes ─────────────────────────────────────────────────────────────────

@app.route("/_internal/health")
def health():
    try:
        conn = get_db()
        conn.close()
        return jsonify({"status": "ok", "db": "connected"})
    except Exception as e:
        return jsonify({"status": "degraded", "db": str(e)}), 503


@app.route("/api/report")
def api_report():
    """
    Main data endpoint for the dashboard.
    Returns total events, severity counts, attack summary,
    and top 20 attackers ranked by threat score.
    Supports optional query params:
      ?severity=HIGH   — filter events by severity
      ?service=api-service — filter by service
      ?ip=1.2.3.4      — filter by source IP
    """
    severity_filter = request_arg("severity")
    service_filter  = request_arg("service")
    ip_filter       = request_arg("ip")

    try:
        conn = get_db()
        cur  = conn.cursor()

        # Build WHERE clause dynamically
        conditions = []
        params = []
        if severity_filter:
            conditions.append("severity = %s")
            params.append(severity_filter)
        if service_filter:
            conditions.append("service = %s")
            params.append(service_filter)
        if ip_filter:
            conditions.append("source_ip = %s")
            params.append(ip_filter)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # Total event count
        cur.execute(f"SELECT COUNT(*) AS total FROM events {where}", params)
        total = cur.fetchone()["total"]

        # Severity breakdown
        cur.execute(f"""
            SELECT severity, COUNT(*) AS count
            FROM events {where}
            GROUP BY severity
        """, params)
        severity_counts = {row["severity"]: row["count"] for row in cur.fetchall()}

        # Attack type summary
        cur.execute(f"""
            SELECT attack_type, COUNT(*) AS count
            FROM events {where}
            GROUP BY attack_type
            ORDER BY count DESC
        """, params)
        attack_summary = {row["attack_type"]: row["count"] for row in cur.fetchall()}

        # Top 20 attackers by threat score
        cur.execute("""
            SELECT source_ip, event_count, threat_score,
                   top_severity, attack_types, first_seen, last_seen
            FROM attacker_profiles
            ORDER BY threat_score DESC
            LIMIT 20
        """)
        attackers = []
        for row in cur.fetchall():
            attackers.append({
                "ip":            row["source_ip"],
                "event_count":   row["event_count"],
                "threat_score":  row["threat_score"],
                "top_severity":  row["top_severity"],
                "attack_types":  row["attack_types"] or [],
                "first_seen":    row["first_seen"].isoformat() if row["first_seen"] else None,
                "last_seen":     row["last_seen"].isoformat()  if row["last_seen"]  else None,
            })

        # Recent 50 events (for live feed)
        cur.execute(f"""
            SELECT timestamp, service, source_ip, attack_type, severity, path, action
            FROM events {where}
            ORDER BY timestamp DESC
            LIMIT 50
        """, params)
        recent_events = []
        for row in cur.fetchall():
            recent_events.append({
                "timestamp":   row["timestamp"].isoformat() if row["timestamp"] else None,
                "service":     row["service"],
                "source_ip":   row["source_ip"],
                "attack_type": row["attack_type"],
                "severity":    row["severity"],
                "path":        row["path"],
                "action":      row["action"],
            })

        conn.close()

        return jsonify({
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "total_events":    total,
            "severity_counts": severity_counts,
            "attack_summary":  attack_summary,
            "attackers":       attackers,
            "recent_events":   recent_events,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/events")
def api_events():
    """Paginated event log. ?page=1&limit=50"""
    page  = max(1, int(request_arg("page")  or 1))
    limit = min(100, int(request_arg("limit") or 50))
    offset = (page - 1) * limit

    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            SELECT timestamp, service, source_ip, method,
                   path, action, attack_type, severity
            FROM events
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r["timestamp"]:
                r["timestamp"] = r["timestamp"].isoformat()
        conn.close()
        return jsonify({"page": page, "limit": limit, "events": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/attacker/<ip>")
def api_attacker(ip):
    """Full event history for a single attacker IP."""
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            SELECT timestamp, service, method, path,
                   action, attack_type, severity
            FROM events
            WHERE source_ip = %s
            ORDER BY timestamp DESC
        """, (ip,))
        events = []
        for row in cur.fetchall():
            e = dict(row)
            if e["timestamp"]:
                e["timestamp"] = e["timestamp"].isoformat()
            events.append(e)
        conn.close()
        return jsonify({"ip": ip, "events": events})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Helper ─────────────────────────────────────────────────────────────────────
def request_arg(name):
    from flask import request
    return request.args.get(name, "").strip() or None


# ── Static frontend ────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    # Wait for Postgres before starting Flask
    for attempt in range(10):
        try:
            conn = get_db()
            conn.close()
            print("[+] Database connected.")
            break
        except Exception as e:
            print(f"[!] Waiting for DB ({attempt+1}/10): {e}")
            time.sleep(3)

    app.run(host="0.0.0.0", port=5003, debug=False)