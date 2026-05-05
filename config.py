# config.py

import os

# ─── Base Paths ───────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DATA_DIR        = os.path.join(BASE_DIR, "data")
EVIDENCE_DIR    = os.path.join(DATA_DIR, "evidence")
LOG_DIR         = os.path.join(DATA_DIR, "logs")
PCAP_DIR        = os.path.join(DATA_DIR, "pcap")
REPORT_DIR      = os.path.join(BASE_DIR, "reports")
DB_DIR          = os.path.join(BASE_DIR, "db")

# ─── Database ─────────────────────────────────────────────────────────────────
DB_PATH         = os.path.join(DB_DIR, "dfir.db")

# ─── API Keys (replace with your real keys) ───────────────────────────────────
VIRUSTOTAL_API_KEY  = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY   = "YOUR_ABUSEIPDB_API_KEY"

# ─── Threat Intel Settings ────────────────────────────────────────────────────
VT_URL          = "https://www.virustotal.com/api/v3/ip_addresses/{}"
ABUSE_URL       = "https://api.abuseipdb.com/api/v2/check"

# ─── Alert Severity Levels ────────────────────────────────────────────────────
SEVERITY = {
    "LOW":      1,
    "MEDIUM":   2,
    "HIGH":     3,
    "CRITICAL": 4
}

# ─── IOC Patterns (regex) ─────────────────────────────────────────────────────
import re

IP_PATTERN      = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
DOMAIN_PATTERN  = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|co|info|biz|xyz|top|ru|cn)\b'
)
HASH_PATTERN    = re.compile(r'\b[a-fA-F0-9]{32,64}\b')

# ─── Log Analysis Thresholds ──────────────────────────────────────────────────
FAILED_LOGIN_THRESHOLD  = 5    # >5 failed logins = HIGH alert
PORT_SCAN_THRESHOLD     = 15   # >15 unique ports from one IP = CRITICAL

# ─── Dashboard ────────────────────────────────────────────────────────────────
FLASK_HOST      = "0.0.0.0"
FLASK_PORT      = 5000
FLASK_DEBUG     = True

# ─── Ensure all directories exist ─────────────────────────────────────────────
for _dir in [EVIDENCE_DIR, LOG_DIR, PCAP_DIR, REPORT_DIR, DB_DIR]:
    os.makedirs(_dir, exist_ok=True)
