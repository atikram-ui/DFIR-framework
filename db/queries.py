# db/queries.py
# Pre-built queries used across all modules

from db.database import execute_query, fetch_all, fetch_one, fetch_count
from datetime import datetime, timezone


# ─── Helpers ──────────────────────────────────────────────────────────────────

def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def next_id(prefix: str, table: str, id_col: str) -> str:
    """
    Auto-generate IDs like EVD-001, ALT-042, IOC-007 etc.
    """
    count = fetch_count(f"SELECT COUNT(*) FROM {table}")
    return f"{prefix}-{str(count + 1).zfill(3)}"


# ─── Evidence ─────────────────────────────────────────────────────────────────

def insert_evidence(filename, filepath, file_type,
                    file_size, acquired_by="investigator",
                    description="") -> str:
    eid = next_id("EVD", "evidence", "evidence_id")
    execute_query("""
        INSERT INTO evidence
            (evidence_id, filename, filepath, file_type,
             file_size, acquired_by, acquired_at, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (eid, filename, filepath, file_type,
          file_size, acquired_by, now(), description))
    return eid


def get_all_evidence() -> list[dict]:
    return fetch_all("SELECT * FROM evidence ORDER BY acquired_at DESC")


def get_evidence_by_id(eid: str) -> dict | None:
    return fetch_one("SELECT * FROM evidence WHERE evidence_id=?", (eid,))


def update_evidence_status(eid: str, status: str) -> None:
    execute_query(
        "UPDATE evidence SET status=? WHERE evidence_id=?",
        (status, eid)
    )


# ─── Hashes ───────────────────────────────────────────────────────────────────

def insert_hash(evidence_id, sha256,
                verified_by="system", is_valid=1, notes="") -> None:
    execute_query("""
        INSERT INTO hashes
            (evidence_id, sha256, verified_at, verified_by, is_valid, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (evidence_id, sha256, now(), verified_by, is_valid, notes))


def get_hash_by_evidence(eid: str) -> dict | None:
    return fetch_one(
        "SELECT * FROM hashes WHERE evidence_id=? ORDER BY id DESC LIMIT 1",
        (eid,)
    )


def get_all_hashes() -> list[dict]:
    return fetch_all("SELECT * FROM hashes ORDER BY verified_at DESC")


# ─── Custody Log ──────────────────────────────────────────────────────────────

def log_custody(evidence_id, action,
                performed_by="investigator", notes="") -> None:
    execute_query("""
        INSERT INTO custody_log
            (evidence_id, action, performed_by, performed_at, notes)
        VALUES (?, ?, ?, ?, ?)
    """, (evidence_id, action, performed_by, now(), notes))


def get_custody_log(eid: str) -> list[dict]:
    return fetch_all(
        "SELECT * FROM custody_log WHERE evidence_id=? ORDER BY performed_at",
        (eid,)
    )


# ─── Alerts ───────────────────────────────────────────────────────────────────


def get_all_alerts(severity=None) -> list[dict]:
    if severity:
        return fetch_all(
            "SELECT * FROM alerts WHERE severity=? ORDER BY created_at DESC",
            (severity,)
        )
    return fetch_all("SELECT * FROM alerts ORDER BY created_at DESC")


def get_alert_count_by_severity() -> dict:
    rows = fetch_all("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
    """)
    return {r['severity']: r['count'] for r in rows}


# ─── Log Events ───────────────────────────────────────────────────────────────

def insert_log_event(evidence_id, event_type, source_ip,
                     username, timestamp, raw_line,
                     severity="LOW", flagged=0) -> None:
    execute_query("""
        INSERT INTO log_events
            (evidence_id, event_type, source_ip, username,
             timestamp, raw_line, severity, flagged)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (evidence_id, event_type, source_ip, username,
          timestamp, raw_line, severity, flagged))


def get_flagged_log_events() -> list[dict]:
    return fetch_all(
        "SELECT * FROM log_events WHERE flagged=1 ORDER BY timestamp"
    )


# ─── Network Events ───────────────────────────────────────────────────────────

def insert_network_event(evidence_id, src_ip, dst_ip, src_port,
                         dst_port, protocol, packet_size,
                         timestamp, flags="", summary="",
                         flagged=0) -> None:
    execute_query("""
        INSERT INTO network_events
            (evidence_id, src_ip, dst_ip, src_port, dst_port,
             protocol, packet_size, timestamp, flags, summary, flagged)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (evidence_id, src_ip, dst_ip, src_port, dst_port,
          protocol, packet_size, timestamp, flags, summary, flagged))


def get_flagged_network_events() -> list[dict]:
    return fetch_all(
        "SELECT * FROM network_events WHERE flagged=1 ORDER BY timestamp"
    )


# ─── IOCs ─────────────────────────────────────────────────────────────────────

def insert_ioc(ioc_type, ioc_value, source,
               evidence_id="", threat_score=0) -> str:
    # Avoid duplicate IOCs
    existing = fetch_one(
        "SELECT ioc_id FROM iocs WHERE ioc_value=? AND ioc_type=?",
        (ioc_value, ioc_type)
    )
    if existing:
        return existing['ioc_id']

    iid = next_id("IOC", "iocs", "ioc_id")
    execute_query("""
        INSERT INTO iocs
            (ioc_id, ioc_type, ioc_value, source,
             evidence_id, extracted_at, threat_score)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (iid, ioc_type, ioc_value, source,
          evidence_id, now(), threat_score))
    return iid


def get_unenriched_iocs() -> list[dict]:
    return fetch_all("SELECT * FROM iocs WHERE enriched=0")


def mark_ioc_enriched(ioc_id: str, score: int) -> None:
    execute_query(
        "UPDATE iocs SET enriched=1, threat_score=? WHERE ioc_id=?",
        (score, ioc_id)
    )


def get_all_iocs() -> list[dict]:
    return fetch_all("SELECT * FROM iocs ORDER BY extracted_at DESC")


# ─── Threat Intel ─────────────────────────────────────────────────────────────

def insert_threat_intel(ioc_id, ioc_value, source_api,
                        threat_score, malicious_count,
                        country, isp, tags, raw_response) -> None:
    execute_query("""
        INSERT INTO threat_intel
            (ioc_id, ioc_value, source_api, threat_score,
             malicious_count, country, isp, tags,
             raw_response, queried_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ioc_id, ioc_value, source_api, threat_score,
          malicious_count, country, isp, tags,
          raw_response, now()))


def get_threat_intel_by_ioc(ioc_id: str) -> list[dict]:
    return fetch_all(
        "SELECT * FROM threat_intel WHERE ioc_id=?", (ioc_id,)
    )


# ─── Correlations ─────────────────────────────────────────────────────────────

def insert_correlation(attacker_ip, attack_stage, related_alerts,
                       related_iocs, confidence, summary) -> str:
    cid = next_id("COR", "correlations", "correlation_id")
    execute_query("""
        INSERT INTO correlations
            (correlation_id, attacker_ip, attack_stage,
             related_alerts, related_iocs, confidence,
             summary, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (cid, attacker_ip, attack_stage, related_alerts,
          related_iocs, confidence, summary, now()))
    return cid


def get_all_correlations() -> list[dict]:
    return fetch_all(
        "SELECT * FROM correlations ORDER BY created_at DESC"
    )


# ─── Timeline ─────────────────────────────────────────────────────────────────

def insert_timeline_event(event_time, event_type, source_module,
                          source_ip, target, description,
                          severity="LOW", correlation_id="",
                          evidence_id="") -> None:
    execute_query("""
        INSERT INTO timeline
            (event_time, event_type, source_module, source_ip,
             target, description, severity, correlation_id, evidence_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (event_time, event_type, source_module, source_ip,
          target, description, severity, correlation_id, evidence_id))


def get_full_timeline() -> list[dict]:
    return fetch_all(
        "SELECT * FROM timeline ORDER BY event_time ASC"
    )


# ─── Dashboard Stats ──────────────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    return {
        "total_evidence":     fetch_count("SELECT COUNT(*) FROM evidence"),
        "total_alerts":       fetch_count("SELECT COUNT(*) FROM alerts"),
        "critical_alerts":    fetch_count(
            "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"
        ),
        "high_alerts":        fetch_count(
            "SELECT COUNT(*) FROM alerts WHERE severity='HIGH'"
        ),
        "total_iocs":         fetch_count("SELECT COUNT(*) FROM iocs"),
        "enriched_iocs":      fetch_count(
            "SELECT COUNT(*) FROM iocs WHERE enriched=1"
        ),
        "total_correlations": fetch_count("SELECT COUNT(*) FROM correlations"),
        "timeline_events":    fetch_count("SELECT COUNT(*) FROM timeline"),
    }

def insert_alert(title, description, severity="MEDIUM",
                 source_module="", source_ip="",
                 evidence_id="", raw_data=""):
    """Insert a new alert with status=OPEN."""
    from db.database import fetch_one, execute_query

    last = fetch_one(
        "SELECT alert_id FROM alerts ORDER BY alert_id DESC LIMIT 1"
    )
    if last:
        try:
            num = int(last["alert_id"].split("-")[1]) + 1
        except Exception:
            num = 1
    else:
        num = 1

    alert_id = f"ALT-{num:03d}"

    execute_query(
        """INSERT INTO alerts
           (alert_id, title, description, severity, status,
            source_module, source_ip, evidence_id, raw_data)
           VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)""",
        (alert_id, title, description, severity.upper(),
         source_module, source_ip, evidence_id, raw_data)
    )
    print(f"[ALERT] Inserted {alert_id} [{severity.upper()}] {title}")
    return alert_id

