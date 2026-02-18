"""
AbyssForge - Scan Engine
Orkestrasi utama: crawl → dispatch modul → kumpulkan temuan → simpan ke DB.
Tidak boleh import database, dashboard, atau reporting secara langsung
(database diinjeksikan dari luar melalui dependency injection).
"""

import asyncio
import importlib
import logging
import time
from typing import List, Optional, Any

from core.config import ScanConfig
from core.crawler import WebCrawler, CrawledURL
from core.http_client import AsyncHTTPClient
from core.finding import Finding

logger = logging.getLogger(__name__)

# Mapping nama modul CLI → path Python module
MODULE_MAP = {
    "sqli":      "modules.injection.sqli",
    "xss":       "modules.injection.xss",
    "xxe":       "modules.injection.xxe",
    "ssti":      "modules.injection.ssti",
    "auth":      "modules.broken_auth.auth_check",
    "misconfig": "modules.misconfig.headers",
    "exposure":  "modules.exposure.sensitive_files",
    "redirect":  "modules.network.open_redirect",
    "csrf":      "modules.network.csrf",
    "ssrf":      "modules.network.ssrf",
}


class ScanEngine:
    """
    Engine utama AbyssForge.

    Alur:
    1. Init AsyncHTTPClient
    2. Crawl target untuk menemukan URL & form
    3. Dispatch setiap modul yang aktif secara async
    4. Kumpulkan Finding dari semua modul
    5. Simpan ke database melalui interface yang diinjeksikan
    6. Tampilkan ringkasan ke stdout
    """

    def __init__(self, config: ScanConfig, db: Any):
        """
        Args:
            config: ScanConfig berisi semua setting scan.
            db:     Objek database (Database dari database.db). Diinjeksikan
                    dari luar agar engine tetap bebas dari import database.
        """
        self.config = config
        self.db = db
        self.findings: List[Finding] = []
        self.crawled_urls: List[CrawledURL] = []
        self.scan_id: Optional[int] = None

    def _load_module(self, name: str) -> Optional[Any]:
        """Lazy-load modul scanner berdasarkan nama CLI."""
        path = MODULE_MAP.get(name)
        if not path:
            logger.warning("Modul tidak dikenal: %s", name)
            return None
        try:
            mod = importlib.import_module(path)
            return mod
        except ImportError as exc:
            logger.error("Gagal load modul %s: %s", name, exc)
            return None

    async def _run_module(
        self,
        module_name: str,
        http: AsyncHTTPClient,
        crawled: List[CrawledURL],
    ) -> List[Finding]:
        """Jalankan satu modul scanner dan kembalikan temuan."""
        mod = self._load_module(module_name)
        if mod is None:
            return []

        if not hasattr(mod, "scan"):
            logger.error("Modul %s tidak memiliki fungsi scan()", module_name)
            return []

        try:
            logger.info("[>] Menjalankan modul: %s", module_name)
            findings = await mod.scan(
                config=self.config,
                http=http,
                crawled=crawled,
            )
            count = len(findings)
            severity_counts = {}
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            summary = ", ".join(f"{v}×{k}" for k, v in severity_counts.items())
            logger.info("[+] Modul %s: %d temuan (%s)", module_name, count, summary or "bersih")
            return findings
        except Exception as exc:
            logger.error("Error di modul %s: %s", module_name, exc, exc_info=True)
            return []

    def _print_finding(self, f: Finding) -> None:
        """Cetak satu temuan ke stdout dengan warna ASCII."""
        colors = {
            "CRITICAL": "\033[91m",  # Merah terang
            "HIGH":     "\033[31m",  # Merah
            "MEDIUM":   "\033[33m",  # Kuning
            "LOW":      "\033[34m",  # Biru
            "INFO":     "\033[37m",  # Abu-abu
        }
        reset = "\033[0m"
        color = colors.get(f.severity, "")
        print(
            f"  {color}[{f.severity:8s}]{reset} {f.title}\n"
            f"           URL: {f.url}"
            + (f"\n           Param: {f.parameter}" if f.parameter else "")
            + (f"\n           Evidence: {f.evidence[:120]}" if f.evidence else "")
        )

    def _print_summary(self, elapsed: float) -> None:
        """Cetak ringkasan scan ke stdout."""
        from core.config import SEVERITY_RANK

        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        print("\n" + "=" * 60)
        print(f"  RINGKASAN SCAN — {self.config.target_url}")
        print("=" * 60)
        print(f"  Total URL di-crawl : {len(self.crawled_urls)}")
        print(f"  Total temuan       : {len(self.findings)}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = counts.get(sev, 0)
            if c:
                print(f"  {sev:<10}: {c}")
        print(f"  Durasi             : {elapsed:.1f} detik")
        print(f"  Scan ID            : {self.scan_id}")
        print("=" * 60)

    async def run(self) -> int:
        """
        Jalankan scan penuh.

        Returns:
            scan_id (int) dari database.
        """
        start_time = time.monotonic()

        async with AsyncHTTPClient(self.config) as http:
            # ── 1. Crawl ─────────────────────────────────────────────
            print(f"\n[*] Memulai crawl: {self.config.target_url}")
            crawler = WebCrawler(self.config, http)
            self.crawled_urls = await crawler.crawl()
            print(f"[+] {len(self.crawled_urls)} URL ditemukan.\n")

            # ── 2. Simpan scan ke DB ───────────────────────────────────
            self.scan_id = self.db.create_scan(
                target=self.config.target_url,
                config=self.config.to_dict(),
            )

            # ── 3. Dispatch modul ─────────────────────────────────────
            tasks = [
                self._run_module(mod_name, http, self.crawled_urls)
                for mod_name in self.config.modules
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    self.findings.extend(result)
                elif isinstance(result, Exception):
                    logger.error("Modul gagal: %s", result)

        # ── 4. Simpan temuan ke DB ─────────────────────────────────
        for finding in self.findings:
            self.db.save_finding(self.scan_id, finding)

        self.db.finish_scan(self.scan_id, total_findings=len(self.findings))

        # ── 5. Output ringkasan ────────────────────────────────────
        elapsed = time.monotonic() - start_time

        if self.findings:
            print("\n[!] TEMUAN KERENTANAN:")
            print("-" * 60)
            # Urutkan: CRITICAL → INFO
            from core.config import SEVERITY_RANK
            sorted_findings = sorted(
                self.findings,
                key=lambda f: SEVERITY_RANK.get(f.severity, 0),
                reverse=True,
            )
            for f in sorted_findings:
                self._print_finding(f)
        else:
            print("\n[+] Tidak ada kerentanan yang ditemukan.")

        self._print_summary(elapsed)
        return self.scan_id
