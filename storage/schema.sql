CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    overall_severity TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    check_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);