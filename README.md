<div align="center">

# 🔍 DFIR Correlation Framework
### Digital Forensics & Incident Response Investigation System

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-black?style=for-the-badge&logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue?style=for-the-badge&logo=sqlite)
![License](https://img.shields.io/badge/License-Academic-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

> A complete end-to-end Digital Forensics and Incident Response (DFIR) framework  
> built in Python that unifies evidence collection, integrity verification,  
> log analysis, network forensics, IOC extraction, and threat intelligence  
> correlation into a single investigation pipeline with a Flask web dashboard.

**M.Sc. Digital Forensics & Information Security — Final Year Project**  
**National Forensic Sciences University, Gandhinagar, Gujarat, India**

</div>

---

## 📌 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Technologies Used](#technologies-used)
- [API Configuration](#api-configuration)
- [Database Schema](#database-schema)
- [Screenshots](#screenshots)
- [Author](#author)

---

## 🧠 Overview

Cyber incidents targeting sensitive networks have become increasingly sophisticated,
yet most forensic tools operate in isolation — unable to correlate host-based artifacts,
network evidence, and external threat intelligence in a unified manner.

This project addresses that gap by building an **Integrated DFIR Correlation Framework**
that treats digital forensics as a single end-to-end pipeline rather than a collection
of disconnected tools.

### Problem Statement
- Existing forensic tools are fragmented and do not communicate with each other
- No built-in evidence integrity or chain-of-custody in most workflows
- Threat intelligence is rarely integrated into active investigation pipelines
- Timeline reconstruction across multiple evidence domains is done manually

### Solution
A modular, layered investigation framework that automates the entire process from
evidence acquisition to structured forensic reporting.

---

## ✨ Features

| Phase | Module | Description |
|-------|--------|-------------|
| 01 | Environment Setup | Project structure, virtual environment, dependencies |
| 02 | Database Design | SQLite schema for all investigation data |
| 03 | Evidence Collection | Collect logs and files, store metadata with timestamps |
| 04 | Integrity Verification | SHA-256 hashing, tamper detection, chain of custody |
| 05 | Alert System | Severity-based alerts — LOW / MEDIUM / HIGH / CRITICAL |
| 06 | Log Analysis | Detect failed logins, brute-force, privilege escalation |
| 07 | Network Analysis | Scapy-based packet analysis, C2 traffic detection |
| 08 | IOC Extraction | Extract IPs, domains, hashes, CVEs, emails from all sources |
| 09 | Threat Intelligence | AbuseIPDB + VirusTotal API enrichment with scoring |
| 10 | Correlation Engine | Group events by IP, detect multi-stage attack patterns |
| 11 | Timeline Reconstruction | Chronological attack sequence visualization |
| 12 | Flask Dashboard | Web UI with alerts, graphs, search, and report download |

---

## 🏗️ System Architecture

**Layer 1 — Incident Input** → Disk Images, Memory Dumps, Logs, PCAPs

**Layer 2 — Evidence Acquisition** → Collect, Register, Timestamp, Catalogue

**Layer 3 — Integrity Preservation** → SHA-256 Hashing, Tamper Detection, Chain of Custody

**Layer 4 — Forensic Analysis** → Log Analysis, Network Forensics, IOC Extraction

**Layer 5 — Threat Intelligence** → AbuseIPDB, VirusTotal, Local Threat Feed

**Layer 6 — Reporting and Visualization** → Timeline, Correlation Engine, Flask Dashboard

---

## 📁 Project Structure
dfir_framework/
│
├── modules/
│   ├── evidence_collector.py     # Phase 3 - Evidence collection
│   ├── integrity_checker.py      # Phase 4 - SHA256 hashing & CoC
│   ├── alert_system.py           # Phase 5 - Alert management
│   ├── log_analyzer.py           # Phase 6 - Log parsing & detection
│   ├── network_analyzer.py       # Phase 7 - Packet analysis (Scapy)
│   ├── ioc_extractor.py          # Phase 8 - IOC extraction
│   ├── threat_intel.py           # Phase 9 - Threat intelligence
│   ├── correlation_engine.py     # Phase 10 - Event correlation
│   └── timeline.py               # Phase 11 - Timeline reconstruction
│
├── dashboard/
│   ├── app.py                    # Phase 12 - Flask web application
│   └── templates/
│       ├── index.html
│       ├── alerts.html
│       ├── timeline.html
│       └── correlation.html
│
├── database/
│   └── schema.sql                # Database structure
│
├── evidence/                     # Evidence storage (gitignored)
│
├── bootstrap_db.py               # Database initialization
├── requirements.txt              # Python dependencies
├── .gitignore
└── README.md

---

## ⚙️ Installation

### Prerequisites
- Python 3.10 or higher
- Git
- Linux (Kali / Ubuntu) recommended

### Clone and Setup

```bash
# Clone the repository
git clone https://github.com/atikram-ui/DFIR-framework.git
cd DFIR-framework

# Create virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Initialize database with sample data
python3 bootstrap_db.py
```

---

## 🚀 Usage

### Run Individual Modules

```bash
# Phase 3 - Collect evidence
python3 modules/evidence_collector.py

# Phase 4 - Verify integrity
python3 modules/integrity_checker.py

# Phase 6 - Analyze logs
python3 modules/log_analyzer.py

# Phase 7 - Analyze network packets
python3 modules/network_analyzer.py

# Phase 8 - Extract IOCs (with sample data)
python3 modules/ioc_extractor.py --sample

# Phase 9 - Enrich with threat intelligence (offline mode)
python3 modules/threat_intel.py --local

# Phase 9 - Enrich with live APIs
python3 modules/threat_intel.py
```

### Launch Dashboard

```bash
cd dashboard
python3 app.py
```

Open browser at: `http://localhost:5000`

---

## 🔬 Modules

### Evidence Collector
Collects digital artifacts from the system including log files, configuration files,
and system information. Stores metadata (filename, size, type, timestamp) in SQLite.

### Integrity Checker
Implements SHA-256 cryptographic hashing for all evidence files. Detects tampering
by comparing stored hashes against current file hashes. Maintains full chain of custody.

### Log Analyzer
Parses system logs (auth.log, syslog, apache) to detect:
- Failed SSH login attempts
- Brute-force attacks
- Privilege escalation
- Suspicious commands

### Network Analyzer
Uses **Scapy** to analyze packet captures and detect:
- Port scanning (SYN scans)
- C2 beacon traffic
- Data exfiltration patterns
- Suspicious outbound connections

### IOC Extractor
Extracts Indicators of Compromise using regex patterns:
- IP addresses (public only)
- Domains (with suspicious TLD detection)
- File hashes (MD5, SHA1, SHA256)
- URLs, emails, CVEs
- Attack tool user-agents (sqlmap, nmap, masscan)

### Threat Intelligence
Enriches extracted IOCs using:
- **AbuseIPDB** — IP reputation and abuse reports
- **VirusTotal** — Multi-engine malware detection
- **Local feed** — Offline known-bad IP/domain database

Assigns threat scores (0-100) and severity levels (LOW / MEDIUM / HIGH / CRITICAL).

### Correlation Engine
Groups related events by source IP to reconstruct multi-stage attack patterns:
- Reconnaissance → Exploitation → Persistence → Exfiltration

### Timeline Reconstruction
Builds a chronological sequence of all attack events across all evidence sources
for complete incident reconstruction.

---

## 🛠️ Technologies Used

| Category | Technology |
|----------|-----------|
| Language | Python 3.10+ |
| Database | SQLite3 |
| Network Analysis | Scapy |
| Web Framework | Flask |
| Threat Intel | AbuseIPDB API, VirusTotal API |
| Hashing | SHA-256 (hashlib) |
| Visualization | Matplotlib, Chart.js |
| Report Generation | ReportLab |
| Operating System | Kali Linux / Ubuntu |

---

## 🔑 API Configuration

```bash
# Set environment variables — never hardcode API keys
export ABUSEIPDB_KEY="your_abuseipdb_key_here"
export VIRUSTOTAL_KEY="your_virustotal_key_here"
```

**Get free API keys at:**
- AbuseIPDB: https://www.abuseipdb.com/register
- VirusTotal: https://www.virustotal.com/gui/join-us

> Without API keys the system runs in **local feed mode** automatically.
> Use `--local` flag to force offline mode.

---

## 🗄️ Database Schema
evidence_files    → collected evidence metadata
log_events        → parsed log entries
network_packets   → captured packet data
alerts            → generated security alerts
iocs              → extracted indicators of compromise
threat_intel      → API enrichment results
chain_of_custody  → evidence access audit trail

---

## 📸 Screenshots

> Dashboard screenshots will be added after Phase 12 completion.

---

## 👨‍💻 Author

**Atikram Das**
- Enrollment: 240103003015
- Programme: M.Sc. Digital Forensics & Information Security
- School: School of Cyber Security & Digital Forensics
- University: National Forensic Sciences University, Gandhinagar

---

## 👨‍🏫 Supervisor

**Dr. Nilay Mistry**
Associate Dean, SCSDF
National Forensic Sciences University, Gandhinagar

---

## 📅 Project Timeline
January 2026  →  Project initiated
February 2026 →  Phases 1-4 completed (Core Framework)
March 2026    →  Phases 5-8 completed (Analysis Modules)
April 2026    →  Phases 9-12 completed (Intelligence + Dashboard)
April 2026    →  Viva conducted and evaluated satisfactory

---

## ⚠️ Disclaimer

This project is developed strictly for **academic and educational purposes**.
All attack simulations are performed in isolated controlled environments.
Do not use any component of this framework on systems without explicit authorization.

---

<div align="center">

**National Forensic Sciences University, Gandhinagar — April 2026**

⭐ Star this repository if you found it helpful

</div>
