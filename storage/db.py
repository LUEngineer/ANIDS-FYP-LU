import sqlite3
import os
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Path is relative to project root, resolved via .env so nothing is hardcoded
DB_PATH = os.getenv("DB_PATH", "data/anids.db")
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_connection():
    # Foreign key enforcement is off by default in SQLite, must enable per connection
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    # Ensures /data exists before SQLite tries to create the file there
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection()
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def save_scan(result: dict) -> int:
    # result shape: {"target": str, "overall_severity": str, "findings": [{"check": str, "severity": str, "description": str}, ...]}
    conn = get_connection()
    cursor = conn.cursor()

    timestamp = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        "INSERT INTO scans (target, timestamp, overall_severity) VALUES (?, ?, ?)",
        (result["target"], timestamp, result["overall_severity"])
    )
    scan_id = cursor.lastrowid

    for finding in result.get("findings", []):
        cursor.execute(
            "INSERT INTO findings (scan_id, check_name, severity, description) VALUES (?, ?, ?, ?)",
            (scan_id, finding["check"], finding["severity"], finding["description"])
        )

    conn.commit()
    conn.close()
    return scan_id


def get_history() -> list[dict]:
    # Returns scan summaries only, newest first, for a history/list view
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_scan_detail(scan_id: int) -> dict:
    # Returns one scan plus all its findings, for a detail/drill-down view
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan_row = cursor.fetchone()
    if scan_row is None:
        conn.close()
        return None

    cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    finding_rows = cursor.fetchall()
    conn.close()

    scan = dict(scan_row)
    scan["findings"] = [dict(row) for row in finding_rows]
    return scan