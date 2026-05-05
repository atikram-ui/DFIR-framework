import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db_manager import get_db_connection, init_db
from datetime import datetime, timedelta
import random

def seed():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    print("[*] Seeding demo data...")

    alert_data = [
        ("FAILED_LOGIN",    "HIGH",     "192.168.1.105", "192.168.1.1",  "Multiple failed SSH login attempts",      "2026-04-01 08:01:00", "log_analyzer"),
        ("FAILED_LOGIN",    "HIGH",     "192.168.1.105", "192.168.1.1",  "Brute force pattern detected",            "2026-04-01 08:02:10", "log_analyzer"),
        ("PORT_SCAN",       "CRITICAL", "10.0.0.55",     "192.168.1.0",  "SYN scan detected on 1024 ports",         "2026-04-01 08:05:00", "network_analyzer"),
        ("C2_TRAFFIC",      "CRITICAL", "10.0.0.55",     "185.220.101.5","Outbound C2 beacon to malicious IP",       "2026-04-01 08:15:00", "network_analyzer"),
        ("PRIVILEGE_ESC",   "CRITICAL", "192.168.1.105", "192.168.1.1",  "sudo executed after login success",        "2026-04-01 08:20:00", "log_analyzer"),
        ("DATA_EXFIL",      "CRITICAL", "10.0.0.55",     "185.220.101.5","Large outbound transfer 450MB",            "2026-04-01 08:45:00", "network_analyzer"),
        ("FAILED_LOGIN",    "MEDIUM",   "172.16.0.22",   "192.168.1.1",  "Failed FTP login attempts",                "2026-04-01 09:00:00", "log_analyzer"),
        ("SUSP_PROCESS",    "HIGH",     "192.168.1.105", None,           "netcat spawned by www-data",               "2026-04-01 08:22:00", "log_analyzer"),
        ("MALWARE_HASH",    "CRITICAL", "10.0.0.55",     None,           "Known malware hash detected",              "2026-04-01 08:10:00", "ioc_extractor"),
        ("ANOMALOUS_DNS",   "HIGH",     "10.0.0.55",     "8.8.8.8",      "DNS query to known C2 domain",             "2026-04-01 08:12:00", "network_analyzer"),
        ("FAILED_LOGIN",    "LOW",      "203.0.113.42",  "192.168.1.1",  "Single failed login attempt",              "2026-04-01 10:00:00", "log_analyzer"),
        ("PORT_SCAN",       "HIGH",     "172.16.0.22",   "192.168.1.5",  "Aggressive port scan detected",            "2026-04-01 09:05:00", "network_analyzer"),
        ("LATERAL_MOVE",    "CRITICAL", "192.168.1.105", "192.168.1.20", "SMB connection after compromise",          "2026-04-01 08:30:00", "network_analyzer"),
        ("WEBSHELL",        "CRITICAL", "185.220.101.5", "192.168.1.10", "Webshell uploaded to /var/www/html",       "2026-04-01 08:08:00", "log_analyzer"),
        ("INFO",            "INFO",     None,            None,           "Scheduled backup completed",               "2026-04-01 07:00:00", "system"),
    ]
    cursor.executemany("""
        INSERT OR IGNORE INTO alerts
        (alert_type,severity,source_ip,destination_ip,description,timestamp,source_module)
        VALUES (?,?,?,?,?,?,?)
    """, alert_data)

    ioc_data = [
        ("ip",     "185.220.101.5",                   "2026-04-01 08:15:00", "2026-04-01 08:45:00", "network"),
        ("ip",     "10.0.0.55",                       "2026-04-01 08:05:00", "2026-04-01 08:45:00", "network"),
        ("ip",     "192.168.1.105",                   "2026-04-01 08:01:00", "2026-04-01 08:20:00", "log"),
        ("domain", "malware-c2.ru",                   "2026-04-01 08:12:00", "2026-04-01 08:12:00", "dns"),
        ("domain", "evil-payload.com",                "2026-04-01 08:08:00", "2026-04-01 08:08:00", "web"),
        ("hash",   "d41d8cd98f00b204e9800998ecf8427e","2026-04-01 08:10:00", "2026-04-01 08:10:00", "file"),
        ("hash",   "5d41402abc4b2a76b9719d911017c592","2026-04-01 08:11:00", "2026-04-01 08:11:00", "file"),
        ("ip",     "172.16.0.22",                     "2026-04-01 09:00:00", "2026-04-01 09:05:00", "network"),
    ]
    cursor.executemany("""
        INSERT OR IGNORE INTO iocs (ioc_type,ioc_value,first_seen,last_seen,source)
        VALUES (?,?,?,?,?)
    """, ioc_data)

    threat_data = [
        ("185.220.101.5",                    95, 87, "Russia",      "HostKey LLC",         "tor,c2,malware",    "2026-04-01 08:15:00"),
        ("10.0.0.55",                        78, 45, "Unknown",     "Internal",            "scanner,pivot",     "2026-04-01 08:05:00"),
        ("malware-c2.ru",                    98, 92, "Russia",      "Reg.ru",              "c2,botnet,malware", "2026-04-01 08:12:00"),
        ("evil-payload.com",                 90, 80, "Netherlands", "Frantech Solutions",  "malware,phishing",  "2026-04-01 08:08:00"),
        ("d41d8cd98f00b204e9800998ecf8427e", 85, 70, None,         None,                  "ransomware,trojan", "2026-04-01 08:10:00"),
    ]
    cursor.executemany("""
        INSERT OR IGNORE INTO threat_intel
        (ioc_value,threat_score,malicious_count,country,isp,tags,checked_at)
        VALUES (?,?,?,?,?,?,?)
    """, threat_data)

    base = datetime(2026, 4, 1, 8, 0, 0)
    ips = ["10.0.0.55","192.168.1.105","172.16.0.22","185.220.101.5","8.8.8.8"]
    protocols = ["TCP","UDP","ICMP","HTTP","DNS"]
    packets = []
    for i in range(80):
        src = random.choice(ips)
        dst = random.choice(ips)
        proto = random.choice(protocols)
        sport = random.randint(1024, 65535)
        dport = random.choice([22,80,443,8080,3389,445,21,53,random.randint(1,1024)])
        size = random.randint(64, 1500)
        ts = (base + timedelta(minutes=i//2, seconds=random.randint(0,59))).strftime("%Y-%m-%d %H:%M:%S")
        packets.append((src, dst, proto, sport, dport, size, ts))
    cursor.executemany("""
        INSERT INTO network_packets
        (source_ip,dest_ip,protocol,source_port,dest_port,packet_size,timestamp)
        VALUES (?,?,?,?,?,?,?)
    """, packets)

    corr_data = [
        ("10.0.0.55",     "MULTI_STAGE_ATTACK",  6, "2026-04-01 08:05:00", "2026-04-01 08:45:00",
         "Recon to Exploitation to C2 to Exfiltration chain detected", "CRITICAL"),
        ("192.168.1.105", "BRUTE_FORCE_SUCCESS", 4, "2026-04-01 08:01:00", "2026-04-01 08:30:00",
         "Brute force SSH then privilege escalation and lateral movement", "CRITICAL"),
        ("172.16.0.22",   "RECONNAISSANCE",      2, "2026-04-01 09:00:00", "2026-04-01 09:05:00",
         "FTP probing and aggressive port scanning", "HIGH"),
    ]
    cursor.executemany("""
        INSERT OR IGNORE INTO correlations
        (source_ip,attack_stage,event_count,first_seen,last_seen,description,severity)
        VALUES (?,?,?,?,?,?,?)
    """, corr_data)

    timeline_data = [
        ("2026-04-01 08:01:00","FAILED_LOGIN",      "192.168.1.105","192.168.1.1",  "First SSH brute force attempt",         "HIGH",    "log_analyzer"),
        ("2026-04-01 08:02:10","FAILED_LOGIN",      "192.168.1.105","192.168.1.1",  "Continued brute force 23 attempts",     "HIGH",    "log_analyzer"),
        ("2026-04-01 08:05:00","PORT_SCAN",         "10.0.0.55",    "192.168.1.0",  "SYN scan on subnet reconnaissance",     "CRITICAL","network_analyzer"),
        ("2026-04-01 08:08:00","WEBSHELL_UPLOAD",   "185.220.101.5","192.168.1.10", "Webshell uploaded to web server",       "CRITICAL","log_analyzer"),
        ("2026-04-01 08:10:00","MALWARE_DETECTED",  "10.0.0.55",    None,           "Known malware hash found on disk",      "CRITICAL","ioc_extractor"),
        ("2026-04-01 08:12:00","ANOMALOUS_DNS",     "10.0.0.55",    "8.8.8.8",      "DNS query to malware C2 domain",        "HIGH",    "network_analyzer"),
        ("2026-04-01 08:15:00","C2_BEACON",         "10.0.0.55",    "185.220.101.5","First C2 beacon to external server",    "CRITICAL","network_analyzer"),
        ("2026-04-01 08:20:00","LOGIN_SUCCESS",     "192.168.1.105","192.168.1.1",  "SSH login succeeded after brute force", "CRITICAL","log_analyzer"),
        ("2026-04-01 08:22:00","SUSP_PROCESS",      "192.168.1.105",None,           "Netcat spawned by www-data user",       "HIGH",    "log_analyzer"),
        ("2026-04-01 08:30:00","LATERAL_MOVEMENT",  "192.168.1.105","192.168.1.20", "SMB pivot to internal host",            "CRITICAL","network_analyzer"),
        ("2026-04-01 08:45:00","DATA_EXFILTRATION", "10.0.0.55",    "185.220.101.5","450MB exfiltrated to C2 server",        "CRITICAL","network_analyzer"),
        ("2026-04-01 09:00:00","FAILED_LOGIN",      "172.16.0.22",  "192.168.1.1",  "FTP probing from new source IP",        "MEDIUM",  "log_analyzer"),
        ("2026-04-01 09:05:00","PORT_SCAN",         "172.16.0.22",  "192.168.1.5",  "Additional host being scanned",         "HIGH",    "network_analyzer"),
    ]
    cursor.executemany("""
        INSERT INTO timeline_events
        (event_time,event_type,source_ip,destination_ip,description,severity,source_module)
        VALUES (?,?,?,?,?,?,?)
    """, timeline_data)

    conn.commit()
    conn.close()
    print("[+] Demo data seeded successfully!")
    print(f"    Alerts:    {len(alert_data)}")
    print(f"    IOCs:      {len(ioc_data)}")
    print(f"    Packets:   80")
    print(f"    Corr:      {len(corr_data)}")
    print(f"    Timeline:  {len(timeline_data)}")

if __name__ == "__main__":
    seed()
