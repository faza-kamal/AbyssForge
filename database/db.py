"""
AbyssForge - Database Layer (SQLite)
Menyimpan semua hasil scan dan temuan.
Tidak boleh import core, modules, dashboard, atau reporting.
"""

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent.parent / "data" / "abyssforge.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    modules     TEXT    NOT NULL DEFAULT '',
    config      TEXT    NOT NULL DEFAULT '{}',
    status      TEXT    NOT NULL DEFAULT 'running',  -- running / completed / failed
    total_findings INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title           TEXT    NOT NULL,
    vuln_type       TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    cvss_score      REAL    NOT NULL DEFAULT 0.0,
    url             TEXT    NOT NULL,
    parameter       TEXT,
    method          TEXT    NOT NULL DEFAULT 'GET',
    description     TEXT    NOT NULL DEFAULT '',
    evidence        TEXT    NOT NULL DEFAULT '',
    payload         TEXT    NOT NULL DEFAULT '',
    request         TEXT    NOT NULL DEFAULT '',
    response_snippet TEXT   NOT NULL DEFAULT '',
    remediation     TEXT    NOT NULL DEFAULT '',
    refs            TEXT    NOT NULL DEFAULT '',
    module          TEXT    NOT NULL DEFAULT '',
    confidence      TEXT    NOT NULL DEFAULT 'MEDIUM',
    false_positive_risk TEXT NOT NULL DEFAULT 'LOW',
    extra           TEXT    NOT NULL DEFAULT '{}',
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""


class Database:
    """
    Interface SQLite untuk AbyssForge.
    Thread-safe dengan connection per-call.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _init_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(SCHEMA_SQL)
            logger.debug("Database schema diinisialisasi: %s", self.db_path)
        except Exception as exc:
            logger.error("Gagal inisialisasi database: %s", exc)
            raise

    # ─── Scan Operations ──────────────────────────────────────────────────────

    def create_scan(self, target: str, config: Dict[str, Any]) -> int:
        """Buat record scan baru dan kembalikan scan ID."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (target, modules, config, status, created_at)
                VALUES (?, ?, ?, 'running', datetime('now'))
                """,
                (
                    target,
                    config.get("modules", ""),
                    json.dumps(config),
                ),
            )
            conn.commit()
            scan_id = cursor.lastrowid
            logger.debug("Scan dibuat: ID=%d, target=%s", scan_id, target)
            return scan_id

    def finish_scan(self, scan_id: int, total_findings: int) -> None:
        """Tandai scan sebagai selesai."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status='completed', total_findings=?, finished_at=datetime('now')
                WHERE id=?
                """,
                (total_findings, scan_id),
            )
            conn.commit()

    def fail_scan(self, scan_id: int, reason: str = "") -> None:
        """Tandai scan sebagai gagal."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status='failed', finished_at=datetime('now') WHERE id=?",
                (scan_id,),
            )
            conn.commit()

    def get_scan(self, scan_id: int) -> Optional[Dict]:
        """Ambil satu scan berdasarkan ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_all_scans(self) -> List[Dict]:
        """Ambil semua scan, diurutkan dari yang terbaru."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_scan(self, scan_id: int) -> bool:
        """Hapus scan dan semua temuan terkait."""
        with self._connect() as conn:
            conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            conn.commit()
            return True

    # ─── Finding Operations ───────────────────────────────────────────────────

    def save_finding(self, scan_id: int, finding: Any) -> int:
        """
        Simpan satu Finding ke database.
        finding harus memiliki method to_dict().
        """
        d = finding.to_dict()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO findings (
                    scan_id, title, vuln_type, severity, cvss_score,
                    url, parameter, method, description, evidence,
                    payload, request, response_snippet, remediation,
                    refs, module, confidence, false_positive_risk,
                    extra, timestamp
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?
                )
                """,
                (
                    scan_id,
                    d["title"], d["vuln_type"], d["severity"], d["cvss_score"],
                    d["url"], d.get("parameter"), d["method"],
                    d["description"], d["evidence"],
                    d["payload"], d["request"], d["response_snippet"], d["remediation"],
                    d.get("references", ""), d["module"], d["confidence"], d["false_positive_risk"],
                    json.dumps(d.get("extra", {})), d["timestamp"],
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_findings(
        self,
        scan_id: int,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
    ) -> List[Dict]:
        """Ambil temuan berdasarkan scan_id, dengan filter opsional."""
        query = "SELECT * FROM findings WHERE scan_id=?"
        params: List[Any] = [scan_id]

        if severity:
            query += " AND severity=?"
            params.append(severity.upper())
        if vuln_type:
            query += " AND vuln_type=?"
            params.append(vuln_type.lower())

        query += " ORDER BY cvss_score DESC, timestamp ASC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                try:
                    d["extra"] = json.loads(d.get("extra", "{}"))
                except json.JSONDecodeError:
                    d["extra"] = {}
                result.append(d)
            return result

    def get_finding_stats(self, scan_id: int) -> Dict[str, int]:
        """Kembalikan jumlah temuan per severity untuk scan tertentu."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT severity, COUNT(*) as count
                FROM findings WHERE scan_id=?
                GROUP BY severity
                """,
                (scan_id,),
            ).fetchall()
            stats = {r["severity"]: r["count"] for r in rows}
            return stats

    def search_findings(self, keyword: str) -> List[Dict]:
        """Cari temuan berdasarkan keyword di title, url, atau description."""
        kw = f"%{keyword}%"
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT f.*, s.target FROM findings f
                JOIN scans s ON f.scan_id = s.id
                WHERE f.title LIKE ? OR f.url LIKE ? OR f.description LIKE ?
                ORDER BY f.cvss_score DESC
                LIMIT 100
                """,
                (kw, kw, kw),
            ).fetchall()
            return [dict(r) for r in rows]
