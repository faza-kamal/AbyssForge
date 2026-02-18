"""
AbyssForge - Finding Model
Model data untuk setiap kerentanan yang ditemukan.
Tidak boleh import modules, database, dashboard, atau reporting.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from core.config import cvss_to_severity


@dataclass
class Finding:
    """
    Representasi satu temuan kerentanan.
    Dirancang agar bisa diserialisasi ke JSON/SQLite.
    """

    # Identitas
    title: str
    vuln_type: str          # sqli, xss, ssrf, xxe, ssti, csrf, misconfig, exposure, etc.
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cvss_score: float       # 0.0 – 10.0

    # Lokasi
    url: str
    parameter: Optional[str] = None
    method: str = "GET"

    # Detail
    description: str = ""
    evidence: str = ""
    payload: str = ""
    request: str = ""
    response_snippet: str = ""

    # Rekomendasi
    remediation: str = ""
    references: str = ""

    # Meta
    module: str = ""
    confidence: str = "MEDIUM"  # HIGH / MEDIUM / LOW
    false_positive_risk: str = "LOW"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_cvss(cls, cvss_score: float, **kwargs) -> "Finding":
        """Buat Finding dengan severity otomatis dari CVSS score."""
        return cls(severity=cvss_to_severity(cvss_score), cvss_score=cvss_score, **kwargs)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "description": self.description,
            "evidence": self.evidence,
            "payload": self.payload,
            "request": self.request,
            "response_snippet": self.response_snippet,
            "remediation": self.remediation,
            "references": self.references,
            "module": self.module,
            "confidence": self.confidence,
            "false_positive_risk": self.false_positive_risk,
            "timestamp": self.timestamp,
            "extra": self.extra,
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.title} | {self.url}"
            + (f" | param={self.parameter}" if self.parameter else "")
        )
