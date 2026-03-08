import sqlite3
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config import DB_PATH

def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS file_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            operation   TEXT    NOT NULL,
            path        TEXT    NOT NULL,
            extension   TEXT,
            file_size   INTEGER DEFAULT 0,
            risk_score  REAL    DEFAULT 0.0,
            process     TEXT,
            pid         INTEGER,
            label       INTEGER DEFAULT -1,
            session_id  TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            path            TEXT    NOT NULL,
            score           REAL    DEFAULT 0.0,
            entropy         REAL    DEFAULT 0.0,
            is_encrypted    INTEGER DEFAULT 0,
            encryption_conf REAL    DEFAULT 0.0,
            malicious       INTEGER DEFAULT 0,
            reasons         TEXT,
            trigger_op      TEXT,
            label           INTEGER DEFAULT -1,
            session_id      TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS cpu_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            cpu_percent REAL    NOT NULL,
            is_spike    INTEGER DEFAULT 0,
            baseline    REAL    DEFAULT 0.0,
            spike_delta REAL    DEFAULT 0.0,
            label       INTEGER DEFAULT -1,
            session_id  TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS mass_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            operation   TEXT    NOT NULL,
            count       INTEGER NOT NULL,
            window_secs INTEGER NOT NULL,
            process     TEXT,
            severity    TEXT,
            label       INTEGER DEFAULT -1,
            session_id  TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS behavior_sequences (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            session_id  TEXT    NOT NULL,
            features    TEXT    NOT NULL,
            label       INTEGER DEFAULT -1,
            window_size INTEGER DEFAULT 30,
            source      TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            alert_type  TEXT    NOT NULL,
            confidence  REAL    DEFAULT 0.0,
            details     TEXT,
            status      TEXT    DEFAULT "active"
        )
    ''')

    conn.commit()
    conn.close()
    print("[DB] All tables initialized successfully.")
    print(f"[DB] Database path: {DB_PATH}")

if __name__ == "__main__":
    init_db()