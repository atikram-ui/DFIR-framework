"""
Phase 11: Timeline Reconstruction
Merges alerts, IOCs, TI results, and correlations
into a single chronological attack timeline.
"""

import sqlite3, os, json
from datetime import datetime
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(BASE_DIR, "dfir.db")

SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}

STAGE_ICONS = {
    "RECON":        "[RECON      ]",
    "BRUTE_FORCE":  "[BRUTE_FORCE]",
    "EXPLOITATION": "[EXPLOIT    ]",
    "LATERAL":      "[LATERAL    ]",
    "EXFILTRATION": "[EXFIL      ]",
    "PERSISTENCE":  "[PERSIST    ]",
    "THREAT_INTEL": "[THREAT_INTL]",
    "UNKNOWN":      "[UNKNOWN    ]",
    "INFO":         "[INFO       ]",
}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── Table setup ───────────────────────────────────────────────────────────────

def ensure_timeline_table():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timeline (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            source      TEXT DEFAULT '',
            ip_address  TEXT DEFAULT '',
            stage       TEXT DEFAULT 'UNKNOWN',
            description TEXT DEFAULT '',
            severity    TEXT DEFAULT 'LOW',
            data_source TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()
    print("[+] timeline table ready.")

# ── Collect events from all tables ────────────────────────────────────────────

def collect_alert_events():
    """Pull all alerts and map them to timeline format."""
    conn   = get_db()
    rows   = conn.execute("""
        SELECT timestamp, alert_type, source, description, severity
        FROM alerts ORDER BY timestamp ASC
    """).fetchall()
    conn.close()

    import re
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    events = []

    for r in rows:
        ips = ip_pattern.findall((r["description"] or "") + " " + (r["source"] or ""))
        ip  = ips[0] if ips else r["source"] or "unknown"
        events.append({
            "timestamp":   r["timestamp"],
            "event_type":  r["alert_type"],
            "source":      r["source"],
            "ip_address":  ip,
            "stage":       r["alert_type"],
            "description": r["description"],
            "severity":    r["severity"],
            "data_source": "alerts",
        })
    return events


def collect_ti_events():
    """Pull TI enrichment results as timeline events."""
    conn = get_db()
    rows = conn.execute("""
        SELECT ioc_value, ioc_type, source, abuse_score,
               vt_malicious, threat_label, severity, enriched_at
        FROM ti_results ORDER BY enriched_at ASC
    """).fetchall()
    conn.close()

    events = []
    for r in rows:
        desc = (f"TI enrichment: {r['ioc_value']} ({r['ioc_type']}) | "
                f"AbuseIPDB={r['abuse_score']}% | "
                f"VT_malicious={r['vt_malicious']} | "
                f"label={r['threat_label']}")
        events.append({
            "timestamp":   r["enriched_at"],
            "event_type":  "THREAT_INTEL",
            "source":      r["source"],
            "ip_address":  r["ioc_value"] if r["ioc_type"] == "ip" else "",
            "stage":       "THREAT_INTEL",
            "description": desc,
            "severity":    r["severity"],
            "data_source": "ti_results",
        })
    return events


def collect_ioc_events():
    """Pull raw IOC discoveries as timeline events."""
    conn = get_db()
    rows = conn.execute("""
        SELECT value, type, source, timestamp
        FROM iocs ORDER BY timestamp ASC
    """).fetchall()
    conn.close()

    events = []
    for r in rows:
        desc = f"IOC extracted: {r['value']} ({r['type']}) from {r['source']}"
        events.append({
            "timestamp":   r["timestamp"],
            "event_type":  "IOC_EXTRACTED",
            "source":      r["source"],
            "ip_address":  r["value"] if r["type"] == "ip" else "",
            "stage":       "RECON",
            "description": desc,
            "severity":    "LOW",
            "data_source": "iocs",
        })
    return events


def collect_correlation_events():
    """Pull correlation summaries as timeline events."""
    conn = get_db()
    rows = conn.execute("""
        SELECT ip_address, stages, severity, event_count,
               first_seen, last_seen, summary
        FROM correlations ORDER BY first_seen ASC
    """).fetchall()
    conn.close()

    events = []
    for r in rows:
        desc = (f"Correlation: {r['ip_address']} | "
                f"{r['event_count']} events | "
                f"stages={r['stages'] or 'NONE'} | "
                f"{r['summary']}")
        events.append({
            "timestamp":   r["first_seen"] or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_type":  "CORRELATION",
            "source":      r["ip_address"],
            "ip_address":  r["ip_address"],
            "stage":       "UNKNOWN",
            "description": desc,
            "severity":    r["severity"],
            "data_source": "correlations",
        })
    return events

# ── Build unified timeline ────────────────────────────────────────────────────

def build_timeline():
    """Merge all event sources, sort by timestamp, write to timeline table."""
    ensure_timeline_table()

    all_events = []
    all_events += collect_alert_events()
    all_events += collect_ti_events()
    all_events += collect_ioc_events()
    all_events += collect_correlation_events()

    if not all_events:
        print("[!] No events found across any table.")
        return

    # Sort by timestamp, then by severity within same timestamp
    all_events.sort(key=lambda x: (
        x["timestamp"] or "0000",
        SEVERITY_ORDER.get(x["severity"], 9)
    ))

    # Write to timeline table
    conn = get_db()
    conn.execute("DELETE FROM timeline")  # fresh rebuild each run

    for ev in all_events:
        conn.execute("""
            INSERT INTO timeline
              (timestamp, event_type, source, ip_address,
               stage, description, severity, data_source)
            VALUES (?,?,?,?,?,?,?,?)
        """, (ev["timestamp"], ev["event_type"], ev["source"],
              ev["ip_address"], ev["stage"], ev["description"],
              ev["severity"], ev["data_source"]))

    conn.commit()
    conn.close()

    print(f"[+] Timeline built: {len(all_events)} events total.\n")
    print_timeline()

# ── Display timeline ──────────────────────────────────────────────────────────

def print_timeline(ip_filter=None, severity_filter=None, limit=50):
    conn = get_db()

    query  = "SELECT * FROM timeline"
    params = []
    wheres = []

    if ip_filter:
        wheres.append("ip_address = ?")
        params.append(ip_filter)
    if severity_filter:
        wheres.append("severity = ?")
        params.append(severity_filter)
    if wheres:
        query += " WHERE " + " AND ".join(wheres)

    query += " ORDER BY timestamp ASC"
    if limit:
        query += f" LIMIT {limit}"

    rows = conn.execute(query, params).fetchall()
    conn.close()

    if not rows:
        print("[!] No timeline events found.")
        return

    print("=" * 72)
    print("  ATTACK TIMELINE")
    if ip_filter:
        print(f"  Filtered by IP: {ip_filter}")
    print("=" * 72)

    current_ip = None
    for r in rows:
        # Print IP header when IP changes
        if r["ip_address"] and r["ip_address"] != current_ip:
            current_ip = r["ip_address"]
            print(f"\n  ── {current_ip} ──────────────────────────────")

        stage_icon = STAGE_ICONS.get(r["stage"], "[UNKNOWN    ]")
        sev_label  = f"[{r['severity']:<8}]"
        ts         = r["timestamp"][:19] if r["timestamp"] else "unknown"
        desc       = r["description"][:90] if r["description"] else ""

        print(f"  {ts}  {sev_label}  {stage_icon}")
        print(f"    {desc}")

    print("\n" + "=" * 72)
    print_timeline_stats()


def print_timeline_stats():
    conn  = get_db()
    total = conn.execute("SELECT COUNT(*) FROM timeline").fetchone()[0]

    sev_counts = conn.execute("""
        SELECT severity, COUNT(*) as cnt FROM timeline
        GROUP BY severity ORDER BY cnt DESC
    """).fetchall()

    stage_counts = conn.execute("""
        SELECT stage, COUNT(*) as cnt FROM timeline
        GROUP BY stage ORDER BY cnt DESC
    """).fetchall()

    ip_counts = conn.execute("""
        SELECT ip_address, COUNT(*) as cnt FROM timeline
        WHERE ip_address != ''
        GROUP BY ip_address ORDER BY cnt DESC LIMIT 5
    """).fetchall()

    conn.close()

    print(f"\n  Total events : {total}")

    print("\n  By Severity:")
    for r in sev_counts:
        bar = "█" * min(r["cnt"] * 2, 30)
        print(f"    {r['severity']:<10} {bar} ({r['cnt']})")

    print("\n  By Stage:")
    for r in stage_counts:
        print(f"    {r['stage']:<15} {r['cnt']}")

    print("\n  Top IPs by event count:")
    for r in ip_counts:
        print(f"    {r['ip_address']:<20} {r['cnt']} events")


def export_timeline_json(output_path=None):
    """Export timeline to JSON file for dashboard use."""
    if not output_path:
        output_path = os.path.join(BASE_DIR, "reports", "timeline.json")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    conn = get_db()
    rows = conn.execute("SELECT * FROM timeline ORDER BY timestamp ASC").fetchall()
    conn.close()

    data = [dict(r) for r in rows]
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[+] Timeline exported to {output_path} ({len(data)} events)")
    return output_path
