# db/database.py

import sqlite3
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DB_PATH
from db.schema import SCHEMA_SQL


def get_connection() -> sqlite3.Connection:
    """
    Returns a SQLite connection with row_factory set
    so results come back as dict-like Row objects.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")   # better concurrency
    return conn


def initialize_database() -> None:
    """
    Creates all tables if they do not already exist.
    Safe to call multiple times (idempotent).
    """
    print("[DB] Initializing database...")
    conn = get_connection()
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        print(f"[DB] Database ready at: {DB_PATH}")
    except sqlite3.Error as e:
        print(f"[DB][ERROR] {e}")
    finally:
        conn.close()


def execute_query(sql: str, params: tuple = ()) -> None:
    """
    Run INSERT / UPDATE / DELETE — no return value needed.
    """
    conn = get_connection()
    try:
        conn.execute(sql, params)
        conn.commit()
    except sqlite3.IntegrityError as e:
        print(f"[DB][INTEGRITY] {e}")
    except sqlite3.Error as e:
        print(f"[DB][ERROR] {e}")
    finally:
        conn.close()


def fetch_one(sql: str, params: tuple = ()) -> dict | None:
    """
    Returns a single row as a plain dict, or None.
    """
    conn = get_connection()
    try:
        cur = conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None
    except sqlite3.Error as e:
        print(f"[DB][ERROR] {e}")
        return None
    finally:
        conn.close()


def fetch_all(sql: str, params: tuple = ()) -> list[dict]:
    """
    Returns a list of dicts (empty list if nothing found).
    """
    conn = get_connection()
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as e:
        print(f"[DB][ERROR] {e}")
        return []
    finally:
        conn.close()


def fetch_count(sql: str, params: tuple = ()) -> int:
    """
    Returns a single integer count.
    """
    conn = get_connection()
    try:
        cur = conn.execute(sql, params)
        result = cur.fetchone()
        return result[0] if result else 0
    except sqlite3.Error as e:
        print(f"[DB][ERROR] {e}")
        return 0
    finally:
        conn.close()


def table_exists(table_name: str) -> bool:
    """
    Check whether a table exists in the database.
    """
    sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
    result = fetch_one(sql, (table_name,))
    return result is not None
