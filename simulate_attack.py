#!/usr/bin/env python3
"""
DFIR Framework — Attack Simulation Script
Phase 13: Demo Simulation
Simulates a realistic multi-stage APT attack scenario
"""

import sqlite3
import os
import json
import time
import random
import hashlib
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dfir.db")

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
PURPLE = "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def banner():
    print(f"""
{RED}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║         DFIR CORRELATION FRAMEWORK — ATTACK SIMULATOR        ║
║              Phase 13 — Demo & Testing Module                ║
╚══════════════════════════════════════════════════════════════╝
{RESET}
{YELLOW}[!] WARNING: This script simulates a multi-stage APT attack
    for educational/demonstration purposes only.
{RESET}
{CYAN}Scenario: APT Group targeting internal network
  Attacker IP  : 192.168.1.105  (External threat actor)
  Tor Node     : 185.220.101.34 (C2 relay)
  Scanner IP   : 10.0.0.55      (Secondary attacker)
  Target       : 192.168.1.1    (Internal server)
{RESET}""")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log(stage, msg, color=CYAN):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RESET} {color}{BOLD}[{stage}]{RESET} {msg}")
    time.sleep(0.3)

def insert_alert(cursor, alert_type, severity, src_ip, dst_ip, description, module):
    cursor.execute("""
        INSERT INTO alerts (alert_type, severity, source_ip, destination_ip,
                           description, timestamp, source_module, status)
        VALUES (?,?,?,?,?,?,?,'OPEN')
    """, (alert_type, severity, src_ip, dst_ip, description,
          datetime.now().isoformat(), module))

def insert_timeline(cursor, event_type, src_ip, dst_ip, description, severity, module, group_id):
    cursor.execute("""
        INSERT INTO timeline_events
        (event_time, event_type, source_ip, destination_ip,
         description, severity, source_module, group_id)
        VALUES (?,?,?,?,?,?,?,?)
    """, (datetime.now().isoformat(), event_type, src_ip, dst_ip,
          description, severity, module, group_id))

def insert_network(cursor, src_ip, dst_ip, src_port, dst_port, proto, size, flags, payload):
    cursor.execute("""
        INSERT INTO network_events
        (src_ip, dst_ip, src_port, dst_port, protocol,
         packet_size, timestamp, flags, payload_snippet)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (src_ip, dst_ip, src_port, dst_port, proto,
          size, datetime.now().isoformat(), flags, payload))

def insert_ioc(cursor, ioc_type, value, source, threat_score, country, isp, abuse_conf):
    cursor.execute("""
        INSERT OR IGNORE INTO iocs
        (ioc_type, ioc_value, source, first_seen, last_seen,
         threat_score, malicious_count, total_engines, country, isp, abuse_confidence)
        VALUES (?,?,?,?,?,?,?,70,?,?,?)
    """, (ioc_type, value, source,
          datetime.now().isoformat(), datetime.now().isoformat(),
          threat_score, int(threat_score * 0.7), country, isp, abuse_conf))

# ── ATTACK PHASES ────────────────────────────────────────────

def phase_reconnaissance(cursor):
    print(f"\n{PURPLE}{BOLD}{'='*60}")
    print(f"  STAGE 1 — RECONNAISSANCE")
    print(f"{'='*60}{RESET}")

    attacker = "10.0.0.55"
    target_net = "192.168.1.0/24"

    log("RECON", f"Attacker {attacker} begins network discovery scan")
    for port in [22, 80, 443, 3389, 445, 21, 23, 3306]:
        insert_network(cursor, attacker, "192.168.1.1",
                       random.randint(49152, 65535), port,
                       "TCP", random.randint(40, 80), "SYN",
                       f"SYN probe to port {port}")
        log("NET", f"  SYN probe → 192.168.1.1:{port}", DIM)
        time.sleep(0.05)

    insert_alert(cursor, "PORT_SCAN", "HIGH", attacker, target_net,
                 f"TCP SYN scan detected — 8 ports probed on {target_net}", "network_analyzer")
    insert_timeline(cursor, "PORT_SCAN", attacker, target_net,
                    "Initial reconnaissance — TCP SYN port scan across subnet",
                    "HIGH", "network_analyzer", "GRP-SIM-001")
    insert_ioc(cursor, "ip", attacker, "network_analyzer", 55.0, "CN", "Alibaba Cloud", 60)

    log("RECON", f"Open ports identified: 22 (SSH), 80 (HTTP), 443 (HTTPS)", GREEN)
    print(f"  {GREEN}✓ Reconnaissance complete — target fingerprinted{RESET}")

def phase_brute_force(cursor):
    print(f"\n{PURPLE}{BOLD}{'='*60}")
    print(f"  STAGE 2 — CREDENTIAL BRUTE FORCE")
    print(f"{'='*60}{RESET}")

    attacker = "192.168.1.105"
    target   = "192.168.1.1"
    wordlist = ["admin","password","123456","root","toor","kali","letmein","qwerty"]

    log("BRUTE", f"Starting SSH brute force from {attacker} → {target}:22")
    for i, pwd in enumerate(wordlist):
        insert_network(cursor, attacker, target,
                       random.randint(49152, 65535), 22,
                       "TCP", random.randint(100, 300), "PSH,ACK",
                       f"SSH auth attempt: root/{pwd}")
        insert_alert(cursor, "FAILED_LOGIN", "MEDIUM", attacker, target,
                     f"Failed SSH login — user: root, password: {pwd}",
                     "log_analyzer")
        log("FAIL", f"  Login failed: root/{pwd}", YELLOW)
        time.sleep(0.1)

    # Successful login
    log("BRUTE", "Password found! Gaining access...", RED)
    insert_alert(cursor, "BRUTE_FORCE", "HIGH", attacker, target,
                 f"SSH brute force SUCCESS after {len(wordlist)} attempts — root access granted",
                 "log_analyzer")
    insert_alert(cursor, "SUCCESSFUL_LOGIN", "CRITICAL", attacker, target,
                 "Unauthorized SSH login — root credentials compromised", "log_analyzer")
    insert_timeline(cursor, "BRUTE_FORCE", attacker, target,
                    f"SSH brute force attack — {len(wordlist)} attempts, root access gained",
                    "CRITICAL", "log_analyzer", "GRP-SIM-001")
    insert_ioc(cursor, "ip", attacker, "log_analyzer", 85.0, "RU", "HostKey LLC", 92)

    print(f"  {RED}✓ Root access obtained via SSH brute force{RESET}")

def phase_malware_drop(cursor):
    print(f"\n{PURPLE}{BOLD}{'='*60}")
    print(f"  STAGE 3 — MALWARE DEPLOYMENT")
    print(f"{'='*60}{RESET}")

    attacker = "192.168.1.105"
    target   = "192.168.1.1"

    # Fake malware hash
    fake_content = b"MZ_FAKE_MALWARE_PAYLOAD_FOR_DEMO_ONLY_" + os.urandom(32)
    mal_hash = hashlib.sha256(fake_content).hexdigest()

    log("MALWARE", f"Attacker uploads malicious payload via SCP")
    insert_network(cursor, attacker, target,
                   random.randint(49152, 65535), 22,
                   "TCP", 45678, "PSH,ACK",
                   "SCP file transfer — malicious payload")

    log("MALWARE", f"Payload hash: {mal_hash[:32]}...", RED)
    insert_alert(cursor, "MALWARE_DROP", "CRITICAL", attacker, target,
                 f"Malicious file uploaded — SHA256: {mal_hash[:32]}...",
                 "threat_intel")
    insert_alert(cursor, "MALWARE_HASH", "CRITICAL", attacker, None,
                 f"VirusTotal match: 48/70 engines flagged as Trojan.Generic",
                 "threat_intel")
    insert_ioc(cursor, "hash", mal_hash, "threat_intel", 98.0, None, None, 0)
    insert_timeline(cursor, "MALWARE", attacker, target,
                    f"Malicious payload deployed — detected by 48/70 AV engines",
                    "CRITICAL", "threat_intel", "GRP-SIM-001")

    print(f"  {RED}✓ Malware deployed and detected by threat intel module{RESET}")

def phase_privilege_escalation(cursor):
    print(f"\n{PURPLE}{BOLD}{'='*60}")
    print(f"  STAGE 4 — PRIVILEGE ESCALATION")
    print(f"{'='*60}{RESET}")

    attacker = "192.168.1.105"
    target   = "192.168.1.1"

    log("PRIVESC", "Attacker attempts sudo privilege escalation")
    cmds = [
        ("sudo -l", "MEDIUM", "Enumerating sudo permissions"),
        ("sudo /bin/bash -i", "CRITICAL", "Spawning root shell via sudo"),
        ("cat /etc/shadow", "CRITICAL", "Reading shadow password file"),
        ("crontab -e", "HIGH", "Installing persistence via crontab"),
    ]
    for cmd, sev, desc in cmds:
        insert_alert(cursor, "PRIV_ESCALATION", sev, attacker, target,
                     f"{desc} — cmd: `{cmd}`", "log_analyzer")
        log("CMD", f"  $ {cmd}", RED)
        time.sleep(0.15)

    insert_timeline(cursor, "PRIVILEGE_ESCALATION", attacker, target,
                    "Full root privilege escalation — persistence installed via crontab",
                    "CRITICAL", "log_analyzer", "GRP-SIM-001")

    print(f"  {RED}✓ Root shell obtained — persistence established{RESET}")

def phase_lateral_movement(cursor):
    print(f"\n{PURPLE}{BOLD}{'='*60}")
    print(f"  STAGE 5 — LATERAL MOVEMENT")
    print(f"{'='*60}{RESET}")

    attacker = "192.168.1.105"
    targets  = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]

    log("LATERAL", "Attacker pivots to internal network")
    for tgt in targets:
        insert_network(cursor, attacker, tgt,
                       random.randint(49152, 65535), 445,
                       "TCP", random.randint(200, 600), "SYN",
                       "SMB connection attempt — lateral movement")
        insert_alert(cursor, "LATERAL_MOVEMENT", "HIGH", attacker, tgt,
                     f"SMB lateral movement attempt → {tgt}:445", "network_analyzer")
        log("PIVOT", f"  SMB probe → {tgt}:445", YELLOW)
        time.sleep(0.1)

    insert_timeline(cursor, "LATERAL_MOVEMENT", attacker, "192.168.1.0/24",
                    f"Lateral movement via SMB — {len(targets)} internal hosts targeted",
                    "HIGH", "network_analyzer", "GRP-SIM-001")

    print(f"  {YELLOW}✓ Lateral movement detected across {len(targets)} hosts{RESET}")

def phase_c2_communication(cursor):
    print(f"\n{PURPLE}{BOLD}{'='*60}")
    print(f"  STAGE 6 — C2 COMMUNICATION")
    print(f"{'='*60}{RESET}")

    attacker = "192.168.1.105"
    c2       = "185.220.101.34"  # Tor exit node

    log("C2", f"Establishing C2 channel to Tor exit node {c2}")
    for i in range(5):
        insert_network(cursor, attacker, c2,
                       random.randint(49152, 65535), 443,
                       "TCP", random.randint(1000, 5000), "PSH,ACK",
                       "Encrypted C2 beacon over HTTPS/Tor")
        time.sleep(0.1)

    insert_alert(cursor, "C2_COMMUNICATION", "CRITICAL", attacker, c2,
                 "Encrypted C2 communication via Tor exit node — 5 beacons detected",
                 "network_analyzer")
    insert_alert(cursor, "SUSPICIOUS_IP", "CRITICAL", c2, "192.168.1.10",
                 "Tor exit node — known malicious relay (AbuseIPDB score: 100)",
                 "threat_intel")
    insert_ioc(cursor, "ip", c2, "threat_intel", 100.0, "DE", "Tor Exit Relay", 100)
    insert_ioc(cursor, "domain", "evil-c2.onion", "ioc_extractor", 99.0, None, None, 0)
    insert_timeline(cursor, "C2_BEACON", attacker, c2,
                    "Command & Control established via Tor — 5 encrypted beacons",
                    "CRITICAL", "network_analyzer", "GRP-SIM-001")

    print(f"  {RED}✓ C2 channel active — attacker has remote control{RESET}")

def phase_data_exfiltration(cursor):
    print(f"\n{PURPLE}{BOLD}{'='*60}")
    print(f"  STAGE 7 — DATA EXFILTRATION")
    print(f"{'='*60}{RESET}")

    attacker = "192.168.1.105"
    c2       = "185.220.101.34"

    log("EXFIL", "Attacker begins mass data exfiltration")
    total_bytes = 0
    for i in range(6):
        chunk = random.randint(20000000, 50000000)  # 20-50MB per chunk
        total_bytes += chunk
        insert_network(cursor, attacker, c2,
                       random.randint(49152, 65535), 443,
                       "TCP", chunk, "PSH,ACK",
                       f"Data exfil chunk {i+1} — encrypted payload")
        log("EXFIL", f"  Chunk {i+1}: {chunk//1024//1024}MB transferred", RED)
        time.sleep(0.15)

    total_mb = total_bytes // 1024 // 1024
    insert_alert(cursor, "DATA_EXFILTRATION", "CRITICAL", attacker, c2,
                 f"Mass data exfiltration — {total_mb}MB transferred to C2 server",
                 "network_analyzer")
    insert_timeline(cursor, "DATA_EXFIL", attacker, c2,
                    f"Data exfiltration complete — {total_mb}MB sent via encrypted channel",
                    "CRITICAL", "network_analyzer", "GRP-SIM-001")

    print(f"  {RED}✓ {total_mb}MB of data exfiltrated to C2{RESET}")

def phase_dns_tunneling(cursor):
    print(f"\n{PURPLE}{BOLD}{'='*60}")
    print(f"  STAGE 8 — DNS TUNNELING (Secondary Attacker)")
    print(f"{'='*60}{RESET}")

    attacker2 = "10.0.0.55"

    log("DNS", f"Secondary attacker {attacker2} using DNS tunneling")
    suspicious_domains = [
        "a1b2c3d4.evil-tunnel.com",
        "xfr0data.exfil-dns.net",
        "beacon001.c2-dns.io",
    ]
    for domain in suspicious_domains:
        insert_network(cursor, attacker2, "8.8.8.8",
                       random.randint(49152, 65535), 53,
                       "UDP", random.randint(200, 500), "",
                       f"DNS TXT query: {domain}")
        insert_alert(cursor, "DNS_TUNNELING", "HIGH", attacker2, "8.8.8.8",
                     f"Suspicious DNS TXT query — covert channel: {domain}",
                     "network_analyzer")
        insert_ioc(cursor, "domain", domain, "ioc_extractor", 80.0, None, None, 0)
        log("DNS", f"  TXT query: {domain}", YELLOW)
        time.sleep(0.1)

    insert_timeline(cursor, "DNS_TUNNELING", attacker2, "8.8.8.8",
                    "DNS tunneling covert channel — 3 suspicious TXT queries",
                    "HIGH", "network_analyzer", "GRP-SIM-002")

    print(f"  {YELLOW}✓ DNS tunneling covert channel detected{RESET}")

def build_correlation(cursor):
    print(f"\n{PURPLE}{BOLD}{'='*60}")
    print(f"  CORRELATION ENGINE — Grouping Attack Events")
    print(f"{'='*60}{RESET}")

    groups = [
        ("GRP-SIM-001", "192.168.1.105",
         json.dumps(["RECONNAISSANCE","BRUTE_FORCE","MALWARE_DROP",
                     "PRIVILEGE_ESCALATION","LATERAL_MOVEMENT",
                     "C2_COMMUNICATION","DATA_EXFILTRATION"]),
         "CRITICAL",
         "Full APT kill-chain: recon → brute force → malware → privesc → lateral → C2 → exfil"),
        ("GRP-SIM-002", "10.0.0.55",
         json.dumps(["PORT_SCAN","DNS_TUNNELING"]),
         "HIGH",
         "Secondary attacker: port scan + DNS tunneling covert channel"),
    ]

    for g in groups:
        cursor.execute("""
            INSERT OR REPLACE INTO correlation_groups
            (group_id, attacker_ip, attack_stages, first_seen, last_seen,
             severity, description, total_events)
            VALUES (?,?,?,datetime('now','-30 minutes'),datetime('now'),?,?,
            (SELECT COUNT(*) FROM timeline_events WHERE group_id=?))
        """, (g[0], g[1], g[2], g[3], g[4], g[0]))
        log("CORR", f"  Group {g[0]} — {g[3]} — {g[1]}", PURPLE)

    print(f"  {GREEN}✓ Correlation groups built — attack chain mapped{RESET}")

def run_simulation():
    banner()
    input(f"\n{CYAN}Press ENTER to start simulation...{RESET}\n")

    if not os.path.exists(DB_PATH):
        print(f"{RED}[ERROR] Database not found at {DB_PATH}")
        print(f"Run: python database/db_manager.py first{RESET}")
        return

    conn = get_db()
    cursor = conn.cursor()

    stages = [
        (phase_reconnaissance,    "Stage 1/8 — Reconnaissance"),
        (phase_brute_force,       "Stage 2/8 — Brute Force"),
        (phase_malware_drop,      "Stage 3/8 — Malware Drop"),
        (phase_privilege_escalation,"Stage 4/8 — Privilege Escalation"),
        (phase_lateral_movement,  "Stage 5/8 — Lateral Movement"),
        (phase_c2_communication,  "Stage 6/8 — C2 Communication"),
        (phase_data_exfiltration, "Stage 7/8 — Data Exfiltration"),
        (phase_dns_tunneling,     "Stage 8/8 — DNS Tunneling"),
    ]

    for fn, label in stages:
        fn(cursor)
        conn.commit()
        time.sleep(0.5)

    build_correlation(cursor)
    conn.commit()

    # Summary
    total_alerts   = cursor.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    total_iocs     = cursor.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    total_net      = cursor.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]
    total_timeline = cursor.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0]
    total_groups   = cursor.execute("SELECT COUNT(*) FROM correlation_groups").fetchone()[0]

    conn.close()

    print(f"""
{GREEN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║              SIMULATION COMPLETE — SUMMARY                   ║
╚══════════════════════════════════════════════════════════════╝{RESET}
{CYAN}
  Alerts Generated  : {RED}{total_alerts}{CYAN}
  IOCs Extracted    : {YELLOW}{total_iocs}{CYAN}
  Network Events    : {YELLOW}{total_net}{CYAN}
  Timeline Events   : {GREEN}{total_timeline}{CYAN}
  Correlation Groups: {PURPLE}{total_groups}{CYAN}

  → Open dashboard: {BOLD}http://127.0.0.1:5000{RESET}
{RESET}""")

if __name__ == "__main__":
    run_simulation()
