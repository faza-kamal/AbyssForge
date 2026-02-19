"""
AbyssForge - Scan Configuration
Dataclass untuk menyimpan semua pengaturan scan.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class ScanConfig:
    """Konfigurasi untuk satu sesi scan."""

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

    # User-Agent default yang menyerupai browser
    DEFAULT_UA: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )

    def get_headers(self) -> Dict[str, str]:
        """Kembalikan headers HTTP lengkap menyerupai browser sungguhan."""
        headers = {
            "User-Agent": self.user_agent or self.DEFAULT_UA,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }
        if self.cookie:
            headers["Cookie"] = self.cookie
        headers.update(self.extra_headers)
        return headers
