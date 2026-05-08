"""
CloudTrap — Dashboard Service
PostgreSQL-backed monitoring dashboard with:
- report API
- events API
- attacker details API
- world attack map API
- live stream API
Runs on port 5003.
"""

import os
import time
import json
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from flask import Flask, jsonify, Response, send_from_directory, request

app = Flask(__name__, static_folder="static")


def get_db():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=int(os.getenv("POSTGRES_PORT", 5432)),
        dbname=os.getenv("POSTGRES_DB", "cloudtrap"),
        user=os.getenv("POSTGRES_USER", "cloudtrap"),
        password=os.getenv("POSTGRES_PASSWORD", "cloudtrap"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def request_arg(name):
    return request.args.get(name, "").strip() or None


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
    severity_filter = request_arg("severity")
    service_filter = request_arg("service")
    ip_filter = request_arg("ip")

    conn = None

    try:
        conn = get_db()
        cur = conn.cursor()

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

        cur.execute(f"SELECT COUNT(*) AS total FROM events {where}", params)
        total = cur.fetchone()["total"]

        cur.execute(f"""
            SELECT severity, COUNT(*) AS count
            FROM events {where}
            GROUP BY severity
        """, params)
        severity_counts = {row["severity"]: row["count"] for row in cur.fetchall()}

        cur.execute(f"""
            SELECT attack_type, COUNT(*) AS count
            FROM events {where}
            GROUP BY attack_type
            ORDER BY count DESC
        """, params)
        attack_summary = {row["attack_type"]: row["count"] for row in cur.fetchall()}

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
                "ip": row["source_ip"],
                "event_count": row["event_count"],
                "threat_score": row["threat_score"],
                "top_severity": row["top_severity"],
                "attack_types": row["attack_types"] or [],
                "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
            })

        cur.execute(f"""
            SELECT timestamp, service, source_ip, attack_type, severity,
                   path, action, country, city, isp, latitude, longitude
            FROM events {where}
            ORDER BY inserted_at DESC
            LIMIT 50
        """, params)

        recent_events = []

        for row in cur.fetchall():
            recent_events.append({
                "timestamp": row["timestamp"].isoformat() if row["timestamp"] else None,
                "service": row["service"],
                "source_ip": row["source_ip"],
                "attack_type": row["attack_type"],
                "severity": row["severity"],
                "path": row["path"],
                "action": row["action"],
                "country": row["country"],
                "city": row["city"],
                "isp": row["isp"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
            })

        return jsonify({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": total,
            "severity_counts": severity_counts,
            "attack_summary": attack_summary,
            "attackers": attackers,
            "recent_events": recent_events,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()


@app.route("/api/events")
def api_events():
    page = max(1, int(request_arg("page") or 1))
    limit = min(100, int(request_arg("limit") or 50))
    offset = (page - 1) * limit

    conn = None

    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT timestamp, service, source_ip, method,
                   path, action, attack_type, severity,
                   country, city, isp, latitude, longitude
            FROM events
            ORDER BY inserted_at DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))

        rows = []

        for row in cur.fetchall():
            event = dict(row)
            if event["timestamp"]:
                event["timestamp"] = event["timestamp"].isoformat()
            rows.append(event)

        return jsonify({
            "page": page,
            "limit": limit,
            "events": rows
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()


@app.route("/api/attack-map")
def api_attack_map():
    """
    Returns geolocated attack events for map visualization.
    Used by the dashboard world attack map.
    """
    conn = None

    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT source_ip, country, city, isp,
                   latitude, longitude, attack_type, severity,
                   COUNT(*) AS event_count,
                   MAX(inserted_at) AS last_seen
            FROM events
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
            GROUP BY source_ip, country, city, isp,
                     latitude, longitude, attack_type, severity
            ORDER BY last_seen DESC
            LIMIT 200
        """)

        attacks = []

        for row in cur.fetchall():
            attacks.append({
                "source_ip": row["source_ip"],
                "country": row["country"],
                "city": row["city"],
                "isp": row["isp"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
                "attack_type": row["attack_type"],
                "severity": row["severity"],
                "event_count": row["event_count"],
                "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
            })

        return jsonify(attacks)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()


@app.route("/api/attacker/<ip>")
def api_attacker(ip):
    conn = None

    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT timestamp, service, method, path,
                   action, attack_type, severity,
                   country, city, isp, latitude, longitude
            FROM events
            WHERE source_ip = %s
            ORDER BY inserted_at DESC
        """, (ip,))

        events = []

        for row in cur.fetchall():
            event = dict(row)
            if event["timestamp"]:
                event["timestamp"] = event["timestamp"].isoformat()
            events.append(event)

        return jsonify({
            "ip": ip,
            "events": events
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()


@app.route("/api/stream")
def api_stream():
    """
    Lightweight live stream endpoint.
    The dashboard can connect to this with EventSource for near-real-time updates.
    """

    def generate():
        while True:
            try:
                conn = get_db()
                cur = conn.cursor()

                cur.execute("""
                    SELECT timestamp, service, source_ip, attack_type,
                           severity, country, city
                    FROM events
                    ORDER BY inserted_at DESC
                    LIMIT 10
                """)

                rows = []

                for row in cur.fetchall():
                    event = dict(row)
                    if event["timestamp"]:
                        event["timestamp"] = event["timestamp"].isoformat()
                    rows.append(event)

                conn.close()

                payload = {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "events": rows,
                }

                yield f"data: {json.dumps(payload)}\n\n"

            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

            time.sleep(5)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    for attempt in range(10):
        try:
            conn = get_db()
            conn.close()
            print("[+] Database connected.")
            break
        except Exception as e:
            print(f"[!] Waiting for DB ({attempt + 1}/10): {e}")
            time.sleep(3)

    app.run(host="0.0.0.0", port=5003, debug=False)