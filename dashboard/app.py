from flask import Flask, render_template, request, jsonify, send_file
import sqlite3
import os
import json
import csv
import io
from datetime import datetime

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dfir.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── HELPER ──────────────────────────────────────────────────
def severity_order(s):
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0)

# ── ROUTES ──────────────────────────────────────────────────

@app.route("/")
def index():
    db = get_db()
    # Summary cards
    total_alerts   = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    critical_alerts= db.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
    total_iocs     = db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    open_alerts    = db.execute("SELECT COUNT(*) FROM alerts WHERE status='OPEN'").fetchone()[0]
    total_groups   = db.execute("SELECT COUNT(*) FROM correlation_groups").fetchone()[0]
    total_events   = db.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0]

    # Severity breakdown for pie chart
    sev_rows = db.execute("""
        SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity
    """).fetchall()
    sev_data = {r["severity"]: r["cnt"] for r in sev_rows}

    # Alerts per hour for line chart (last 6 hours)
    hourly = db.execute("""
        SELECT strftime('%H:00', timestamp) as hr, COUNT(*) as cnt
        FROM alerts GROUP BY hr ORDER BY hr
    """).fetchall()
    hourly_labels = [r["hr"] for r in hourly]
    hourly_values = [r["cnt"] for r in hourly]

    # Alert type breakdown for bar chart
    type_rows = db.execute("""
        SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type ORDER BY cnt DESC LIMIT 8
    """).fetchall()
    type_labels = [r["alert_type"] for r in type_rows]
    type_values = [r["cnt"] for r in type_rows]

    # Top attacker IPs
    top_ips = db.execute("""
        SELECT source_ip, COUNT(*) as cnt FROM alerts
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip ORDER BY cnt DESC LIMIT 5
    """).fetchall()

    # Recent 5 critical alerts
    recent = db.execute("""
        SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5
    """).fetchall()

    db.close()
    return render_template("index.html",
        total_alerts=total_alerts, critical_alerts=critical_alerts,
        total_iocs=total_iocs, open_alerts=open_alerts,
        total_groups=total_groups, total_events=total_events,
        sev_data=json.dumps(sev_data),
        hourly_labels=json.dumps(hourly_labels),
        hourly_values=json.dumps(hourly_values),
        type_labels=json.dumps(type_labels),
        type_values=json.dumps(type_values),
        top_ips=top_ips, recent=recent
    )

@app.route("/alerts")
def alerts():
    db      = get_db()
    severity= request.args.get("severity", "")
    keyword = request.args.get("q", "")
    src_ip  = request.args.get("ip", "")
    page    = int(request.args.get("page", 1))
    per_page= 15

    query  = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        query += " AND severity=?";   params.append(severity)
    if keyword:
        query += " AND (description LIKE ? OR alert_type LIKE ?)";params += [f"%{keyword}%",f"%{keyword}%"]
    if src_ip:
        query += " AND source_ip=?";  params.append(src_ip)

    total   = db.execute(f"SELECT COUNT(*) FROM ({query})", params).fetchone()[0]
    query  += f" ORDER BY timestamp DESC LIMIT {per_page} OFFSET {(page-1)*per_page}"
    rows    = db.execute(query, params).fetchall()
    db.close()

    pages = (total + per_page - 1) // per_page
    return render_template("alerts.html", alerts=rows, page=page, pages=pages,
                           severity=severity, q=keyword, ip=src_ip, total=total)

@app.route("/correlation")
def correlation():
    db     = get_db()
    groups = db.execute("SELECT * FROM correlation_groups ORDER BY severity DESC, total_events DESC").fetchall()
    result = []
    for g in groups:
        stages = json.loads(g["attack_stages"]) if g["attack_stages"] else []
        related = db.execute("""
            SELECT * FROM alerts WHERE source_ip=? ORDER BY timestamp
        """, (g["attacker_ip"],)).fetchall()
        result.append({"group": g, "stages": stages, "alerts": related})
    db.close()
    return render_template("correlation.html", groups=result)

@app.route("/timeline")
def timeline():
    db      = get_db()
    group_id= request.args.get("group", "")
    query   = "SELECT * FROM timeline_events WHERE 1=1"
    params  = []
    if group_id:
        query += " AND group_id=?"; params.append(group_id)
    query  += " ORDER BY event_time ASC"
    events  = db.execute(query, params).fetchall()
    groups  = db.execute("SELECT DISTINCT group_id FROM timeline_events").fetchall()
    db.close()
    return render_template("timeline.html", events=events, groups=groups, selected=group_id)

@app.route("/iocs")
def iocs():
    db   = get_db()
    rows = db.execute("SELECT * FROM iocs ORDER BY threat_score DESC").fetchall()
    db.close()
    return render_template("reports.html", iocs=rows)

# ── API ENDPOINTS (for AJAX / charts) ─────────────────────

@app.route("/api/stats")
def api_stats():
    db = get_db()
    data = {
        "total_alerts":    db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "critical":        db.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0],
        "high":            db.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0],
        "medium":          db.execute("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'").fetchone()[0],
        "low":             db.execute("SELECT COUNT(*) FROM alerts WHERE severity='LOW'").fetchone()[0],
        "total_iocs":      db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
        "total_groups":    db.execute("SELECT COUNT(*) FROM correlation_groups").fetchone()[0],
        "network_events":  db.execute("SELECT COUNT(*) FROM network_events").fetchone()[0],
    }
    db.close()
    return jsonify(data)

@app.route("/api/alerts/update_status", methods=["POST"])
def update_alert_status():
    data    = request.json
    alert_id= data.get("id")
    status  = data.get("status")
    db = get_db()
    db.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
    db.commit()
    db.close()
    return jsonify({"success": True})

# ── REPORT DOWNLOAD ────────────────────────────────────────

@app.route("/report/csv")
def report_csv():
    db   = get_db()
    rows = db.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Type","Severity","Source IP","Dest IP","Description","Timestamp","Module","Status"])
    for r in rows:
        writer.writerow([r["id"],r["alert_type"],r["severity"],r["source_ip"],
                         r["destination_ip"],r["description"],r["timestamp"],
                         r["source_module"],r["status"]])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"dfir_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

@app.route("/report/iocs/csv")
def report_iocs_csv():
    db   = get_db()
    rows = db.execute("SELECT * FROM iocs ORDER BY threat_score DESC").fetchall()
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Type","Value","Source","Threat Score","Malicious","Country","ISP","Abuse Confidence"])
    for r in rows:
        writer.writerow([r["id"],r["ioc_type"],r["ioc_value"],r["source"],
                         r["threat_score"],r["malicious_count"],r["country"],r["isp"],r["abuse_confidence"]])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"dfir_iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
