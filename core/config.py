"""
AbyssForge - Core Configuration
Tidak boleh import modules, database, dashboard, atau reporting.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class ScanConfig:
    """Konfigurasi global untuk satu sesi scan."""

    target_url: str
    modules: List[str] = field(default_factory=lambda: ["sqli", "xss", "misconfig", "exposure"])
    max_threads: int = 10
    timeout: int = 10
    crawl_depth: int = 2
    delay: float = 0.5
    user_agent: Optional[str] = None
    cookie: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)
    verbose: bool = False
    follow_redirects: bool = True
    verify_ssl: bool = False
    max_urls_per_domain: int = 200
    proxy: Optional[str] = None

    # Severity threshold — temuan di bawah ini tidak dilaporkan
    min_severity: str = "INFO"

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "modules": ",".join(self.modules),
            "max_threads": self.max_threads,
            "timeout": self.timeout,
            "crawl_depth": self.crawl_depth,
            "delay": self.delay,
            "user_agent": self.user_agent or "AbyssForge/1.0",
            "cookie": self.cookie,
            "extra_headers": self.extra_headers,
            "verbose": self.verbose,
            "follow_redirects": self.follow_redirects,
            "verify_ssl": self.verify_ssl,
            "proxy": self.proxy,
        }


# Konstanta severity level
SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

# Konstanta CVSS score range → severity mapping
CVSS_TO_SEVERITY = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFO"),
]


def cvss_to_severity(cvss_score: float) -> str:
    """Konversi CVSS score ke label severity."""
    for threshold, label in CVSS_TO_SEVERITY:
        if cvss_score >= threshold:
            return label
    return "INFO"
