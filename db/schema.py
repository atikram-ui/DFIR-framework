# db/schema.py
# Single source of truth for every table in the DFIR database

SCHEMA_SQL = """

-- ─────────────────────────────────────────────────────────────
-- TABLE 1: evidence
-- Stores every collected file/artifact with metadata
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    NOT NULL UNIQUE,   -- e.g. EVD-001
    filename        TEXT    NOT NULL,
    filepath        TEXT    NOT NULL,
    file_type       TEXT,                      -- disk/memory/log/pcap
    file_size       INTEGER,                   -- bytes
    acquired_by     TEXT    DEFAULT 'investigator',
    acquired_at     TEXT    NOT NULL,          -- ISO timestamp
    description     TEXT,
    status          TEXT    DEFAULT 'ACQUIRED' -- ACQUIRED/VERIFIED/COMPROMISED
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 2: hashes
-- SHA256 fingerprints for tamper detection
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hashes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    NOT NULL,
    sha256          TEXT    NOT NULL,
    verified_at     TEXT    NOT NULL,
    verified_by     TEXT    DEFAULT 'system',
    is_valid        INTEGER DEFAULT 1,         -- 1=valid, 0=tampered
    notes           TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 3: custody_log
-- Every access/action on any evidence item
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS custody_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT    NOT NULL,
    action          TEXT    NOT NULL,  -- ACQUIRED/HASHED/ANALYSED/TRANSFERRED
    performed_by    TEXT    DEFAULT 'investigator',
    performed_at    TEXT    NOT NULL,
    notes           TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 4: alerts
-- All alerts raised by any analysis module
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT    NOT NULL UNIQUE,   -- ALT-001
    title           TEXT    NOT NULL,
    description     TEXT,
    severity        TEXT    NOT NULL,          -- LOW/MEDIUM/HIGH/CRITICAL
    source_module   TEXT,                      -- log/network/ioc/intel
    source_ip       TEXT,
    evidence_id     TEXT,
    raw_data        TEXT,
    created_at      TEXT    NOT NULL,
    is_reviewed     INTEGER DEFAULT 0          -- 0=pending, 1=reviewed
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 5: log_events
-- Parsed entries from system/auth/application logs
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS log_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT,
    event_type      TEXT,       -- FAILED_LOGIN/SUDO/SERVICE/REBOOT etc
    source_ip       TEXT,
    username        TEXT,
    timestamp       TEXT,
    raw_line        TEXT,
    severity        TEXT    DEFAULT 'LOW',
    flagged         INTEGER DEFAULT 0   -- 1 if suspicious
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 6: network_events
-- Parsed packet/connection data
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS network_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    packet_size     INTEGER,
    timestamp       TEXT,
    flags           TEXT,       -- SYN/ACK/RST etc
    summary         TEXT,
    flagged         INTEGER DEFAULT 0
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 7: iocs
-- Indicators of Compromise extracted from any source
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id          TEXT    NOT NULL UNIQUE,   -- IOC-001
    ioc_type        TEXT    NOT NULL,          -- IP/DOMAIN/HASH/URL
    ioc_value       TEXT    NOT NULL,
    source          TEXT,                      -- which log/pcap it came from
    evidence_id     TEXT,
    extracted_at    TEXT    NOT NULL,
    enriched        INTEGER DEFAULT 0,         -- 0=not yet, 1=done
    threat_score    INTEGER DEFAULT 0          -- 0-100
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 8: threat_intel
-- Results from VirusTotal / AbuseIPDB enrichment
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_intel (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id          TEXT    NOT NULL,
    ioc_value       TEXT    NOT NULL,
    source_api      TEXT,                      -- VIRUSTOTAL/ABUSEIPDB
    threat_score    INTEGER DEFAULT 0,         -- 0-100
    malicious_count INTEGER DEFAULT 0,
    country         TEXT,
    isp             TEXT,
    tags            TEXT,                      -- JSON or comma-sep
    raw_response    TEXT,                      -- full API JSON
    queried_at      TEXT    NOT NULL,
    FOREIGN KEY (ioc_id) REFERENCES iocs(ioc_id)
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 9: correlations
-- Grouped multi-stage attack events by IP / campaign
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS correlations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id  TEXT    NOT NULL UNIQUE,   -- COR-001
    attacker_ip     TEXT,
    attack_stage    TEXT,   -- RECON/EXPLOIT/LATERAL/EXFIL
    related_alerts  TEXT,   -- comma-separated alert_ids
    related_iocs    TEXT,   -- comma-separated ioc_ids
    confidence      TEXT    DEFAULT 'MEDIUM',  -- LOW/MEDIUM/HIGH
    summary         TEXT,
    created_at      TEXT    NOT NULL
);

-- ─────────────────────────────────────────────────────────────
-- TABLE 10: timeline
-- Final ordered reconstruction of attack events
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS timeline (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time      TEXT    NOT NULL,          -- ISO timestamp
    event_type      TEXT    NOT NULL,          -- what happened
    source_module   TEXT,                      -- which module found it
    source_ip       TEXT,
    target          TEXT,                      -- target IP/user/service
    description     TEXT,
    severity        TEXT    DEFAULT 'LOW',
    correlation_id  TEXT,
    evidence_id     TEXT
);

"""
