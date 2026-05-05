"""
Phase 10: Correlation Engine
Groups alerts/IOCs by IP, detects multi-stage attack chains,
scores campaigns, and stores results in SQLite.
"""

import sqlite3, json, os
from datetime import datetime
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(BASE_DIR, "dfir.db")

# ── Attack stage keywords ─────────────────────────────────────────────────────
STAGE_KEYWORDS = {
    "RECON":          ["scan", "nmap", "ping", "probe", "enumerat", "recon",
                       "port scan", "discovery"],
    "BRUTE_FORCE":    ["failed login", "invalid user", "authentication failure",
                       "failed password", "brute", "repeated login"],
    "EXPLOITATION":   ["exploit", "payload", "shellcode", "injection", "overflow",
                       "CVE", "vulnerability", "malware", "trojan", "backdoor"],
    "LATERAL":        ["lateral", "pivot", "psexec", "wmi", "rdp", "smb",
                       "pass the hash", "mimikatz", "credential"],
    "EXFILTRATION":   ["exfil", "upload", "transfer", "data sent", "outbound",
                       "dns tunnel", "c2", "command and control", "beacon"],
    "PERSISTENCE":    ["crontab", "startup", "registry", "scheduled task",
                       "autorun", "persistence", "backdoor installed"],
}

SEVERITY_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── Table setup ───────────────────────────────────────────────────────────────

def ensure_tables():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS correlations (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address    TEXT NOT NULL,
            event_count   INTEGER DEFAULT 0,
            stages        TEXT DEFAULT "",
            severity      TEXT DEFAULT "LOW",
            ti_score      INTEGER DEFAULT 0,
            first_seen    TEXT,
            last_seen     TEXT,
            summary       TEXT DEFAULT "",
            created_at    TEXT NOT NULL,
            UNIQUE(ip_address)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attack_chains (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address    TEXT NOT NULL,
            stage         TEXT NOT NULL,
            event_desc    TEXT NOT NULL,
            source        TEXT DEFAULT "",
            timestamp     TEXT NOT NULL,
            severity      TEXT DEFAULT "LOW"
        )
    """)
    conn.commit()
    conn.close()
    print("[+] correlations + attack_chains tables ready.")

# ── Helpers ───────────────────────────────────────────────────────────────────

def detect_stage(text):
    """Return the attack stage name if any keyword matches, else None."""
    text_lower = text.lower()
    for stage, keywords in STAGE_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                return stage
    return None

def score_severity(stages, ti_score):
    """
    Combine stage count + TI score into one severity label.
    More stages = more advanced attack = higher severity.
    """
    stage_count = len(stages)
    if stage_count >= 4 or ti_score >= 3:
        return "CRITICAL"
    elif stage_count >= 3 or ti_score >= 2:
        return "HIGH"
    elif stage_count >= 2 or ti_score >= 1:
        return "MEDIUM"
    return "LOW"

def get_ti_score_for_ip(ip):
    """Get the highest numeric severity score for this IP from ti_results."""
    conn = get_db()
    row  = conn.execute("""
        SELECT severity FROM ti_results
        WHERE ioc_value = ? ORDER BY
        CASE severity
          WHEN 'CRITICAL' THEN 4
          WHEN 'HIGH'     THEN 3
          WHEN 'MEDIUM'   THEN 2
          ELSE 1
        END DESC LIMIT 1
    """, (ip,)).fetchone()
    conn.close()
    if row:
        return SEVERITY_SCORE.get(row["severity"], 0)
    return 0

# ── Core correlation ──────────────────────────────────────────────────────────

def correlate_by_ip():
    """
    Pull all alerts, group them by IP/source,
    detect attack stages, and write to correlations + attack_chains.
    """
    ensure_tables()
    conn = get_db()

    # Fetch all alerts
    alerts = conn.execute("""
        SELECT id, timestamp, alert_type, source, description, severity
        FROM alerts
        ORDER BY timestamp ASC
    """).fetchall()

    # Also fetch IOCs grouped by IP
    iocs = conn.execute("""
        SELECT value, type, source FROM iocs WHERE type = 'ip'
    """).fetchall()

    conn.close()

    if not alerts and not iocs:
        print("[!] No alerts or IOCs found. Run earlier phases first.")
        return

    # ── Group events by IP ────────────────────────────────────────────────────
    ip_events = defaultdict(list)

    # Extract IPs from alert descriptions and sources
    import re
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

    for alert in alerts:
        desc = alert["description"] or ""
        src  = alert["source"]      or ""
        # Find IPs mentioned in the alert
        found_ips = ip_pattern.findall(desc + " " + src)
        if found_ips:
            for ip in set(found_ips):
                ip_events[ip].append({
                    "timestamp":  alert["timestamp"],
                    "alert_type": alert["alert_type"],
                    "source":     alert["source"],
                    "description":alert["description"],
                    "severity":   alert["severity"],
                })
        else:
            # No IP found — group under the source name
            ip_events[src].append({
                "timestamp":  alert["timestamp"],
                "alert_type": alert["alert_type"],
                "source":     alert["source"],
                "description":alert["description"],
                "severity":   alert["severity"],
            })

    # Add IOC IPs to the map too
    for ioc in iocs:
        ip = ioc["value"]
        if ip not in ip_events:
            ip_events[ip] = []

    print(f"[*] Correlating {len(ip_events)} unique IP/source group(s)...\n")

    # ── Process each IP group ─────────────────────────────────────────────────
    conn = get_db()
    total_chains = 0

    for ip, events in ip_events.items():
        stages_detected = set()
        timestamps      = []
        chain_entries   = []

        for ev in events:
            ts   = ev["timestamp"]
            desc = ev["description"]
            sev  = ev["severity"]
            src  = ev["source"]

            stage = detect_stage(desc)
            if stage:
                stages_detected.add(stage)

            timestamps.append(ts)
            chain_entries.append({
                "stage":     stage or "UNKNOWN",
                "desc":      desc,
                "source":    src,
                "timestamp": ts,
                "severity":  sev,
            })

        # Sort chain by timestamp
        chain_entries.sort(key=lambda x: x["timestamp"])

        first_seen = min(timestamps) if timestamps else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen  = max(timestamps) if timestamps else first_seen
        ti_score   = get_ti_score_for_ip(ip)
        severity   = score_severity(stages_detected, ti_score)
        stages_str = ",".join(sorted(stages_detected))
        summary    = (f"{len(events)} events | stages: {stages_str or 'NONE'} | "
                      f"TI score: {ti_score}")
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Write to correlations table
        try:
            conn.execute("""
                INSERT INTO correlations
                  (ip_address, event_count, stages, severity, ti_score,
                   first_seen, last_seen, summary, created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip_address) DO UPDATE SET
                  event_count = excluded.event_count,
                  stages      = excluded.stages,
                  severity    = excluded.severity,
                  ti_score    = excluded.ti_score,
                  last_seen   = excluded.last_seen,
                  summary     = excluded.summary
            """, (ip, len(events), stages_str, severity, ti_score,
                  first_seen, last_seen, summary, created_at))
        except Exception as e:
            print(f"  [!] Correlation insert error for {ip}: {e}")

        # Write attack chain entries
        for entry in chain_entries:
            try:
                conn.execute("""
                    INSERT INTO attack_chains
                      (ip_address, stage, event_desc, source, timestamp, severity)
                    VALUES (?,?,?,?,?,?)
                """, (ip, entry["stage"], entry["desc"][:300],
                      entry["source"], entry["timestamp"], entry["severity"]))
                total_chains += 1
            except Exception as e:
                print(f"  [!] Chain insert error: {e}")

        stage_display = stages_str if stages_str else "NO STAGES DETECTED"
        print(f"  [{severity:<8}] {ip:<20} | {len(events):>3} events | "
              f"stages: {stage_display}")

    conn.commit()
    conn.close()

    print(f"\n[+] Wrote {total_chains} attack chain entries.")
    print_correlation_summary()

# ── Summary output ────────────────────────────────────────────────────────────

def print_correlation_summary():
    conn = get_db()
    rows = conn.execute("""
        SELECT ip_address, event_count, stages, severity, ti_score,
               first_seen, last_seen
        FROM correlations
        ORDER BY CASE severity
          WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM'   THEN 3 ELSE 4 END,
          event_count DESC
    """).fetchall()
    conn.close()

    if not rows:
        print("[!] No correlations found.")
        return

    print("\n" + "="*72)
    print(f"{'IP / SOURCE':<22} {'EVENTS':<8} {'SEVERITY':<10} "
          f"{'TI':<4} {'STAGES'}")
    print("-"*72)
    for r in rows:
        stages = r["stages"] if r["stages"] else "—"
        print(f"{r['ip_address']:<22} {r['event_count']:<8} "
              f"{r['severity']:<10} {r['ti_score']:<4} {stages}")
    print("="*72)

    # Show multi-stage attacks
    multi = [r for r in rows if r["stages"] and "," in r["stages"]]
    if multi:
        print(f"\n[!] MULTI-STAGE ATTACKS DETECTED: {len(multi)}")
        for r in multi:
            print(f"    {r['ip_address']} → {r['stages']} [{r['severity']}]")

def print_attack_chain(ip):
    """Print the full attack chain for a specific IP."""
    conn  = get_db()
    rows  = conn.execute("""
        SELECT stage, event_desc, source, timestamp, severity
        FROM attack_chains WHERE ip_address = ?
        ORDER BY timestamp ASC
    """, (ip,)).fetchall()
    conn.close()

    if not rows:
        print(f"[!] No chain found for {ip}")
        return

    print(f"\n{'='*60}")
    print(f"  Attack Chain for: {ip}")
    print(f"{'='*60}")
    for i, r in enumerate(rows, 1):
        print(f"  Step {i:02d} [{r['timestamp']}]")
        print(f"    Stage   : {r['stage']}")
        print(f"    Severity: {r['severity']}")
        print(f"    Source  : {r['source']}")
        print(f"    Event   : {r['event_desc'][:120]}")
        print()
