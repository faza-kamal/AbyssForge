"""
AbyssForge Database Models
Stores scan results in SQLite for historical tracking.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from abyssforge.core.exceptions import DatabaseError
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.db")


class DatabaseStorage:
    """SQLite storage for scan results and findings."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        target_url TEXT NOT NULL,
        start_time REAL NOT NULL,
        end_time REAL,
        total_findings INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        technologies TEXT,
        waf_detected TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        vuln_type TEXT NOT NULL,
        url TEXT NOT NULL,
        parameter TEXT,
        payload TEXT,
        severity TEXT NOT NULL,
        confidence TEXT,
        evidence TEXT,
        description TEXT,
        remediation TEXT,
        cwe TEXT,
        extra_info TEXT,
        timestamp TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
    """

    def __init__(self, db_path: str = "abyssforge.db") -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.executescript(self.SCHEMA)
                conn.commit()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to initialize database: {e}")

    def save_scan(self, result: Any) -> None:
        """
        Save a scan result to the database.

        Args:
            result: ScanResult object to save
        """
        counts = result.severity_counts
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scans
                    (scan_id, target_url, start_time, end_time, total_findings,
                     critical_count, high_count, medium_count, low_count,
                     technologies, waf_detected)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.scan_id,
                        result.target_url,
                        result.start_time,
                        result.end_time,
                        len(result.findings),
                        counts.get("critical", 0),
                        counts.get("high", 0),
                        counts.get("medium", 0),
                        counts.get("low", 0),
                        json.dumps(list(result.technologies.keys())),
                        result.waf_detected,
                    ),
                )

                for finding in result.findings:
                    conn.execute(
                        """
                        INSERT INTO findings
                        (scan_id, vuln_type, url, parameter, payload, severity,
                         confidence, evidence, description, remediation, cwe,
                         extra_info, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            result.scan_id,
                            finding.vuln_type,
                            finding.url,
                            finding.parameter,
                            finding.payload,
                            finding.severity,
                            finding.confidence,
                            finding.evidence,
                            finding.description,
                            finding.remediation,
                            finding.cwe,
                            json.dumps(finding.extra_info),
                            finding.timestamp,
                        ),
                    )
                conn.commit()
                logger.info(f"Scan {result.scan_id} saved to database")

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to save scan: {e}")

    def get_scan_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent scan history."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY start_time DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve scan history: {e}")

    def get_findings_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all findings for a specific scan."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity",
                    (scan_id,),
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve findings: {e}")
