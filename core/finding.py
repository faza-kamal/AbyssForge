"""
AbyssForge - Finding Model
Representasi satu temuan kerentanan.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


@dataclass
class Finding:
    """Merepresentasikan satu kerentanan yang ditemukan."""

    title: str
    vuln_type: str
    url: str
    severity: str
    cvss_score: float
    description: str
    evidence: str
    payload: str
    remediation: str
    references: str
    module: str
    parameter: Optional[str] = None
    method: str = "GET"
    confidence: str = "MEDIUM"
    false_positive_risk: str = "LOW"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @classmethod
    def from_cvss(
        cls,
        cvss_score: float,
        title: str,
        vuln_type: str,
        url: str,
        description: str,
        evidence: str,
        payload: str,
        remediation: str,
        references: str,
        module: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        confidence: str = "MEDIUM",
        false_positive_risk: str = "LOW",
    ) -> "Finding":
        return cls(
            title=title,
            vuln_type=vuln_type,
            url=url,
            severity=_severity_from_cvss(cvss_score),
            cvss_score=cvss_score,
            description=description,
            evidence=evidence,
            payload=payload,
            remediation=remediation,
            references=references,
            module=module,
            parameter=parameter,
            method=method,
            confidence=confidence,
            false_positive_risk=false_positive_risk,
        )

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "vuln_type": self.vuln_type,
            "url": self.url,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "parameter": self.parameter,
            "method": self.method,
            "description": self.description,
            "evidence": self.evidence,
            "payload": self.payload,
            "request": "",           # Placeholder untuk future RAW request logging
            "response_snippet": self.evidence[:500] if self.evidence else "",
            "remediation": self.remediation,
            "references": self.references,
            "module": self.module,
            "confidence": self.confidence,
            "false_positive_risk": self.false_positive_risk,
            "timestamp": self.timestamp,
            "extra": {},
        }
