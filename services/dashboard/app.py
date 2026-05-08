"""
CloudTrap — Dashboard Service
PostgreSQL-backed monitoring dashboard with:
- report API
- events API
- attacker details API
- world attack map API
- live stream API
- RBAC authentication (Admin / Analyst)
Runs on port 5003.
"""

import os
import time
import json
import hashlib
import secrets
from datetime import datetime, timezone

import boto3
import ssl
from botocore.exceptions import ClientError
import psycopg2
import boto3
import ssl
from botocore.exceptions import ClientError
import psycopg2.extras
from flask import Flask, jsonify, Response, send_from_directory, request, redirect, make_response

app = Flask(__name__, static_folder="static")

# ==================== RBAC CONFIG ====================
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "cloudtrap2026")
ANALYST_USER = os.getenv("ANALYST_USER", "analyst")
ANALYST_PASS = os.getenv("ANALYST_PASS", "analyst2026")

# Simple token store (in production, use JWT or session)
ACTIVE_TOKENS = {}

def generate_token():
    return secrets.token_hex(32)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_user(username, password):
    if username == ADMIN_USER and password == ADMIN_PASS:
        return "admin"
    if username == ANALYST_USER and password == ANALYST_PASS:
        return "analyst"
    return None

def check_auth():
    """Returns role if authenticated, None if not"""
    token = request.cookies.get("cloudtrap_token")
    if token and token in ACTIVE_TOKENS:
        return ACTIVE_TOKENS[token]
    return None

# ==================== DATABASE ====================
# ==================== SECRETS MANAGER ====================
SECRET_ARN = os.getenv("SECRET_ARN", "arn:aws:secretsmanager:eu-north-1:178942529119:secret:CloudTrap-Dashboard-Credentials-wGZgOG")
AWS_REGION_SM = os.getenv("AWS_REGION", "eu-north-1")

def fetch_secrets():
    try:
        client = boto3.client("secretsmanager", region_name=AWS_REGION_SM)
        response = client.get_secret_value(SecretId=SECRET_ARN)
        print("[+] Secrets loaded from AWS Secrets Manager")
        return json.loads(response["SecretString"])
    except Exception as e:
        print(f"[!] Secrets Manager unavailable ({e}), using env fallback")
        return {}

_secrets = fetch_secrets()
ADMIN_PASS = _secrets.get("ADMIN_PASS", os.getenv("ADMIN_PASS", "cloudtrap2026"))
ANALYST_PASS = _secrets.get("ANALYST_PASS", os.getenv("ANALYST_PASS", "analyst2026"))
POSTGRES_PASSWORD = _secrets.get("POSTGRES_PASSWORD", os.getenv("POSTGRES_PASSWORD", "cloudtrap"))

def get_db():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=int(os.getenv("POSTGRES_PORT", 5432)),
        dbname=os.getenv("POSTGRES_DB", "cloudtrap"),
        user=os.getenv("POSTGRES_USER", "cloudtrap"),
        password=POSTGRES_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def request_arg(name):
    return request.args.get(name, "").strip() or None


# ==================== AUTH ROUTES ====================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        role = validate_user(username, password)
        
        if role:
            token = generate_token()
            ACTIVE_TOKENS[token] = role
            resp = make_response(redirect("/"))
            resp.set_cookie("cloudtrap_token", token, httponly=True, max_age=86400)
            return resp
        else:
            error = "Invalid credentials"
    
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudTrap — Sign In</title>
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{
        background:#0a0e1a;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;
        display:flex;align-items:center;justify-content:center;min-height:100vh;
      }
      .login-card{
        background:#111827;border:1px solid #1e2d45;border-radius:16px;padding:40px;width:380px;
      }
      .logo{font-size:22px;font-weight:700;color:#fff;margin-bottom:4px}
      .logo span{color:#06b6d4}
      .subtitle{font-size:13px;color:#64748b;margin-bottom:28px}
      label{font-size:12px;color:#94a3b8;display:block;margin-bottom:4px}
      input{
        width:100%;padding:10px 12px;background:#0d1321;border:1px solid #1e2d45;border-radius:8px;
        color:#e2e8f0;font-size:14px;margin-bottom:16px;outline:none;transition:border-color .2s
      }
      input:focus{border-color:#06b6d4}
      button{
        width:100%;padding:11px;background:linear-gradient(135deg,#3b82f6,#06b6d4);color:#fff;
        border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;margin-top:4px
      }
      button:hover{opacity:.9}
      .error{background:#3b0a0a;color:#ef4444;border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:16px}
      .hint{font-size:11px;color:#475569;margin-top:20px;text-align:center}
      .hint b{color:#64748b}
    </style>
    </head>
    <body>
    <div class="login-card">
      <div class="logo">Cloud<span>Trap</span></div>
      <div class="subtitle">Authenticate to access the dashboard</div>
      ''' + (f'<div class="error">{error}</div>' if error else '') + '''
      <form method="POST">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autofocus>
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Sign in</button>
      </form>
      <div class="hint">
        <b>Admin:</b> admin / cloudtrap2026 &nbsp;|&nbsp; <b>Analyst:</b> analyst / analyst2026<br><span style="color:#64748b;font-size:10px">🔒 Credentials managed by AWS Secrets Manager</span>
      </div>
    </div>
    </body>
    </html>
    '''


@app.route("/logout")
def logout():
    token = request.cookies.get("cloudtrap_token")
    if token:
        ACTIVE_TOKENS.pop(token, None)
    resp = make_response(redirect("/login"))
    resp.delete_cookie("cloudtrap_token")
    return resp


# ==================== HEALTH ====================
@app.route("/_internal/health")
def health():
    try:
        conn = get_db()
        conn.close()
        return jsonify({"status": "ok", "db": "connected"})
    except Exception as e:
        return jsonify({"status": "degraded", "db": str(e)}), 503


# ==================== API ROUTES (all require auth) ====================
@app.route("/api/report")
def api_report():
    role = check_auth()
    if not role:
        return jsonify({"error": "Unauthorized"}), 401

    severity_filter = request_arg("severity")
    service_filter = request_arg("service")
    cloud_filter = request_arg("cloud_provider")
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

        if cloud_filter:
            conditions.append("cloud_provider = %s")
            params.append(cloud_filter)

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
            "role": role,
        "cloud_provider_filter": cloud_filter or "all",
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()


@app.route("/api/events")
def api_events():
    role = check_auth()
    if not role:
        return jsonify({"error": "Unauthorized"}), 401

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
            "events": rows,
            "role": role,
        "cloud_provider_filter": cloud_filter or "all",
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()


@app.route("/api/attack-map")
def api_attack_map():
    role = check_auth()
    if not role:
        return jsonify({"error": "Unauthorized"}), 401

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
    role = check_auth()
    if not role:
        return jsonify({"error": "Unauthorized"}), 401

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
    role = check_auth()
    if not role:
        return jsonify({"error": "Unauthorized"}), 401

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


# ==================== DASHBOARD (auth required) ====================
@app.route("/")
def index():
    role = check_auth()
    if not role:
        return redirect("/login")
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

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile="/app/certs/cert.pem",
        keyfile="/app/certs/key.pem"
    )
    print("[+] HTTPS enabled with self-signed certificate")
    app.run(host="0.0.0.0", port=5003, debug=False, ssl_context=ssl_context)
