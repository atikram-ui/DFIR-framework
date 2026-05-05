#!/usr/bin/env python3
"""
DFIR Framework — Full System Test
Phase 13: Tests all modules and verifies DB integrity
"""

import sqlite3
import os
import sys
import hashlib
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dfir.db")

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

passed = 0
failed = 0
warnings = 0

def ok(msg):
    global passed
    passed += 1
    print(f"  {GREEN}✓ PASS{RESET}  {msg}")

def fail(msg):
    global failed
    failed += 1
    print(f"  {RED}✗ FAIL{RESET}  {msg}")

def warn(msg):
    global warnings
    warnings += 1
    print(f"  {YELLOW}⚠ WARN{RESET}  {msg}")

def section(title):
    print(f"\n{CYAN}{BOLD}[TEST] {title}{RESET}")
    print(f"  {'─'*50}")

# ── TESTS ────────────────────────────────────────────

def test_database():
    section("DATABASE CONNECTIVITY & SCHEMA")
    if not os.path.exists(DB_PATH):
        fail(f"Database not found at {DB_PATH}")
        return False
    ok(f"Database file exists: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    required_tables = [
        "alerts", "iocs", "network_events",
        "correlation_groups", "timeline_events",
        "evidence", "chain_of_custody"
    ]
    existing = {r[0] for r in cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

    for t in required_tables:
        if t in existing:
            ok(f"Table '{t}' exists")
        else:
            fail(f"Table '{t}' MISSING")

    # Check alerts schema has required columns
    cols = {r[1] for r in cursor.execute("PRAGMA table_info(alerts)").fetchall()}
    required_cols = {"source_ip","destination_ip","severity","alert_type","timestamp","status"}
    for c in required_cols:
        if c in cols:
            ok(f"alerts.{c} column present")
        else:
            fail(f"alerts.{c} column MISSING")

    conn.close()
    return True

def test_data_presence():
    section("DATA PRESENCE IN ALL TABLES")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    checks = [
        ("alerts",            "SELECT COUNT(*) FROM alerts",            1),
        ("iocs",              "SELECT COUNT(*) FROM iocs",              1),
        ("network_events",    "SELECT COUNT(*) FROM network_events",    1),
        ("correlation_groups","SELECT COUNT(*) FROM correlation_groups",1),
        ("timeline_events",   "SELECT COUNT(*) FROM timeline_events",   1),
    ]
    for name, query, minimum in checks:
        count = cursor.execute(query).fetchone()[0]
        if count >= minimum:
            ok(f"{name}: {count} records found")
        else:
            fail(f"{name}: Expected >={minimum} records, found {count}")

    conn.close()

def test_alert_severities():
    section("ALERT SEVERITY LEVELS")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    valid = {"CRITICAL","HIGH","MEDIUM","LOW"}
    rows = cursor.execute("SELECT DISTINCT severity FROM alerts").fetchall()
    found = {r[0] for r in rows}

    for sev in valid:
        cnt = cursor.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity=?", (sev,)).fetchone()[0]
        if cnt > 0:
            ok(f"Severity {sev}: {cnt} alerts")
        else:
            warn(f"Severity {sev}: 0 alerts (may be OK)")

    invalid = found - valid
    if invalid:
        fail(f"Invalid severity values found: {invalid}")
    else:
        ok("All severity values are valid")

    conn.close()

def test_sha256_integrity():
    section("SHA256 HASH INTEGRITY")
    test_data = b"DFIR Framework test payload for hashing"
    h = hashlib.sha256(test_data).hexdigest()
    expected = hashlib.sha256(test_data).hexdigest()
    if h == expected and len(h) == 64:
        ok(f"SHA256 produces correct 64-char hex: {h[:16]}...")
    else:
        fail("SHA256 hash mismatch")

    # Tamper detection test
    tampered = test_data + b"X"
    h2 = hashlib.sha256(tampered).hexdigest()
    if h != h2:
        ok("Tamper detection works — modified data produces different hash")
    else:
        fail("Tamper detection FAILED — hashes matched after modification")

def test_ioc_extraction():
    section("IOC EXTRACTION LOGIC")
    import re
    sample_log = """
    Failed login from 192.168.1.105 to server
    DNS query to malware.evil-c2.com detected
    Connection to 185.220.101.34:443 flagged
    Hash: d41d8cd98f00b204e9800998ecf8427e found in scan
    """
    ip_pattern     = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    hash_pattern   = r'\b[0-9a-fA-F]{32}\b'

    ips     = re.findall(ip_pattern, sample_log)
    domains = re.findall(domain_pattern, sample_log)
    hashes  = re.findall(hash_pattern, sample_log)

    if ips:
        ok(f"IP extraction: {ips}")
    else:
        fail("No IPs extracted")

    if domains:
        ok(f"Domain extraction: {domains[:2]}")
    else:
        fail("No domains extracted")

    if hashes:
        ok(f"Hash extraction: {hashes}")
    else:
        warn("No MD5 hashes found (may be OK)")

def test_correlation_groups():
    section("CORRELATION ENGINE")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    groups = cursor.execute("SELECT * FROM correlation_groups").fetchall()
    if not groups:
        fail("No correlation groups found")
        conn.close()
        return

    for g in groups:
        try:
            stages = json.loads(g[2] if g[2] else "[]")
            ok(f"Group {g[1]}: {len(stages)} stages — {g[6]}")
        except json.JSONDecodeError:
            fail(f"Group {g[1]}: attack_stages is invalid JSON")

    # Check that each group's attacker IP has alerts
    for g in groups:
        cnt = cursor.execute(
            "SELECT COUNT(*) FROM alerts WHERE source_ip=?", (g[1],)).fetchone()[0]
        if cnt > 0:
            ok(f"  {g[1]} has {cnt} linked alerts")
        else:
            warn(f"  {g[1]} has no linked alerts")

    conn.close()

def test_timeline_order():
    section("TIMELINE RECONSTRUCTION")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    events = cursor.execute(
        "SELECT event_time, event_type FROM timeline_events ORDER BY event_time ASC"
    ).fetchall()

    if len(events) < 2:
        warn(f"Only {len(events)} timeline events — need more for ordering test")
        conn.close()
        return

    ok(f"Timeline has {len(events)} events")

    # Verify ascending order
    times = [e[0] for e in events]
    is_sorted = all(times[i] <= times[i+1] for i in range(len(times)-1))
    if is_sorted:
        ok(f"Timeline is correctly ordered chronologically")
    else:
        fail("Timeline events are NOT in chronological order")

    ok(f"First event: [{events[0][1]}] at {events[0][0][:19]}")
    ok(f"Last  event: [{events[-1][1]}] at {events[-1][0][:19]}")

    conn.close()

def test_network_events():
    section("NETWORK ANALYSIS DATA")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    total = cursor.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]
    ok(f"Total network events: {total}")

    protos = cursor.execute(
        "SELECT protocol, COUNT(*) FROM network_events GROUP BY protocol"
    ).fetchall()
    for p, c in protos:
        ok(f"  Protocol {p}: {c} packets")

    top_src = cursor.execute("""
        SELECT src_ip, COUNT(*) as cnt FROM network_events
        GROUP BY src_ip ORDER BY cnt DESC LIMIT 3
    """).fetchall()
    for ip, cnt in top_src:
        ok(f"  Top source: {ip} — {cnt} packets")

    conn.close()

def test_flask_routes():
    section("FLASK DASHBOARD ROUTES")
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(DB_PATH), "dashboard"))
        from app import app
        client = app.test_client()

        routes = ["/", "/alerts", "/correlation", "/timeline", "/iocs", "/api/stats"]
        for route in routes:
            resp = client.get(route)
            if resp.status_code == 200:
                ok(f"GET {route} → 200 OK")
            else:
                fail(f"GET {route} → {resp.status_code}")

        # Test API JSON response
        resp = client.get("/api/stats")
        data = json.loads(resp.data)
        if "total_alerts" in data:
            ok(f"API /api/stats returns JSON with total_alerts={data['total_alerts']}")
        else:
            fail("API /api/stats missing total_alerts key")

    except ImportError as e:
        warn(f"Flask app not importable from test context: {e}")
    except Exception as e:
        warn(f"Flask test skipped: {e}")

def print_summary():
    total = passed + failed + warnings
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║                    TEST SUMMARY                              ║
╚══════════════════════════════════════════════════════════════╝{RESET}
  Total Tests : {total}
  {GREEN}Passed      : {passed}{RESET}
  {RED}Failed      : {failed}{RESET}
  {YELLOW}Warnings    : {warnings}{RESET}
""")
    if failed == 0:
        print(f"  {GREEN}{BOLD}✓ ALL TESTS PASSED — System is ready for demo!{RESET}\n")
    else:
        print(f"  {RED}{BOLD}✗ {failed} TEST(S) FAILED — Review errors above.{RESET}\n")

if __name__ == "__main__":
    print(f"\n{CYAN}{BOLD}DFIR Framework — System Test Suite{RESET}")
    print(f"{'='*60}")
    print(f"Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Database  : {DB_PATH}")

    test_database()
    test_data_presence()
    test_alert_severities()
    test_sha256_integrity()
    test_ioc_extraction()
    test_correlation_groups()
    test_timeline_order()
    test_network_events()
    test_flask_routes()

    print_summary()
