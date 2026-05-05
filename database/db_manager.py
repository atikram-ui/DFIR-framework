import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'dfir.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            file_type TEXT,
            file_size INTEGER,
            sha256_hash TEXT,
            collected_at TEXT DEFAULT (datetime('now')),
            investigator TEXT DEFAULT 'analyst',
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS chain_of_custody (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER,
            action TEXT NOT NULL,
            performed_by TEXT DEFAULT 'analyst',
            timestamp TEXT DEFAULT (datetime('now')),
            details TEXT,
            FOREIGN KEY (evidence_id) REFERENCES evidence(id)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT DEFAULT 'LOW',
            source_ip TEXT,
            destination_ip TEXT,
            description TEXT,
            raw_log TEXT,
            timestamp TEXT DEFAULT (datetime('now')),
            source_module TEXT,
            status TEXT DEFAULT 'OPEN'
        );

        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL UNIQUE,
            first_seen TEXT DEFAULT (datetime('now')),
            last_seen TEXT DEFAULT (datetime('now')),
            source TEXT,
            context TEXT
        );

        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_value TEXT NOT NULL,
            threat_score INTEGER DEFAULT 0,
            malicious_count INTEGER DEFAULT 0,
            country TEXT,
            isp TEXT,
            tags TEXT,
            raw_response TEXT,
            checked_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS network_packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            dest_ip TEXT,
            protocol TEXT,
            source_port INTEGER,
            dest_port INTEGER,
            packet_size INTEGER,
            flags TEXT,
            timestamp TEXT DEFAULT (datetime('now')),
            summary TEXT
        );

        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            attack_stage TEXT,
            event_count INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            description TEXT,
            severity TEXT DEFAULT 'MEDIUM',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            description TEXT,
            severity TEXT DEFAULT 'INFO',
            source_module TEXT,
            raw_data TEXT
        );
    """)
    conn.commit()
    conn.close()
    print(f"[+] Database initialized at: {DB_PATH}")

if __name__ == '__main__':
    init_db()
