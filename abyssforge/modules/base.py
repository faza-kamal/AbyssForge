"""
AbyssForge Base Vulnerability Module
All vulnerability detection modules inherit from this base class.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from abyssforge.core.request import RequestHandler
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.module")


@dataclass
class Finding:
    """Represents a single vulnerability finding."""

    vuln_type: str
    url: str
    parameter: str
    payload: str
    severity: str  # critical, high, medium, low, info
    evidence: str
    description: str
    remediation: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    confidence: str = "medium"  # high, medium, low
    request_method: str = "GET"
    extra_info: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "severity": self.severity,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "confidence": self.confidence,
            "request_method": self.request_method,
            "extra_info": self.extra_info,
            "timestamp": self.timestamp,
        }


class BaseModule(ABC):
    """
    Abstract base class for all vulnerability detection modules.
    Each module implements the scan() method to detect a specific vulnerability type.
    """

    # Module metadata - override in subclasses
    MODULE_NAME: str = "base"
    VULN_TYPE: str = "Unknown"
    SEVERITY: str = "medium"
    CWE: Optional[str] = None
    DESCRIPTION: str = ""
    REMEDIATION: str = ""

    def __init__(
        self,
        request_handler: RequestHandler,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the module.

        Args:
            request_handler: HTTP request handler instance
            config: Optional module-specific configuration
        """
        self.request_handler = request_handler
        self.config = config or {}
        self.findings: List[Finding] = []
        self.logger = get_logger(f"abyssforge.module.{self.MODULE_NAME}")
        self._enabled = True

    @property
    def enabled(self) -> bool:
        """Check if this module is enabled."""
        return self._enabled and self.config.get("enabled", True)

    @abstractmethod
    def scan(self, url: str, **kwargs: Any) -> List[Finding]:
        """
        Perform vulnerability scan against the target URL.

        Args:
            url: Target URL to scan
            **kwargs: Additional scan parameters

        Returns:
            List of Finding objects
        """
        pass

    def add_finding(
        self,
        url: str,
        parameter: str,
        payload: str,
        evidence: str,
        severity: Optional[str] = None,
        description: Optional[str] = None,
        remediation: Optional[str] = None,
        confidence: str = "medium",
        request_method: str = "GET",
        extra_info: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """
        Create and register a finding.

        Args:
            url: Vulnerable URL
            parameter: Vulnerable parameter name
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability
            severity: Override default severity
            description: Override default description
            remediation: Override default remediation
            confidence: Confidence level (high/medium/low)
            request_method: HTTP method used
            extra_info: Additional information dictionary

        Returns:
            Created Finding object
        """
        finding = Finding(
            vuln_type=self.VULN_TYPE,
            url=url,
            parameter=parameter,
            payload=payload,
            severity=severity or self.SEVERITY,
            evidence=evidence,
            description=description or self.DESCRIPTION,
            remediation=remediation or self.REMEDIATION,
            cwe=self.CWE,
            confidence=confidence,
            request_method=request_method,
            extra_info=extra_info or {},
        )

        self.findings.append(finding)
        self.logger.warning(
            f"[{finding.severity.upper()}] {self.VULN_TYPE} found at {url} | "
            f"Param: {parameter} | Payload: {payload[:50]}"
        )

        return finding

    def load_payloads(self, filepath: str) -> List[str]:
        """Load payloads from file."""
        from abyssforge.utils.helpers import load_payloads
        return load_payloads(filepath)

    def measure_baseline(self, url: str) -> float:
        """Measure baseline response time for time-based detection."""
        times = []
        for _ in range(3):
            start = time.monotonic()
            try:
                self.request_handler.get(url)
                times.append(time.monotonic() - start)
            except Exception:
                pass
        return sum(times) / len(times) if times else 0.0

    def get_status(self) -> Dict[str, Any]:
        """Get module scan status."""
        return {
            "module": self.MODULE_NAME,
            "enabled": self.enabled,
            "findings": len(self.findings),
        }
