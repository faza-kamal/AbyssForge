"""
AbyssForge - Scan Engine
Orkestrasi scan: crawl → jalankan modul → simpan hasil.
"""

import asyncio
import logging
import importlib
from typing import List, Dict, Any

from core.config import ScanConfig
from core.crawler import Crawler, CrawledURL
from core.http_client import AsyncHTTPClient
from core.finding import Finding

logger = logging.getLogger(__name__)

# Mapping nama modul → path import
MODULE_MAP = {
    "sqli":      "modules.injection.sqli",
    "xss":       "modules.injection.xss",
    "ssti":      "modules.injection.ssti",
    "xxe":       "modules.injection.xxe",
    "ssrf":      "modules.network.ssrf",
    "csrf":      "modules.network.csrf",
    "redirect":  "modules.network.open_redirect",
    "auth":      "modules.broken_auth.auth_check",
    "misconfig": "modules.misconfig.headers",
    "exposure":  "modules.exposure.sensitive_files",
}


class ScanEngine:
    """
    Engine utama AbyssForge.
    Urutan kerja:
    1. Crawl target untuk kumpulkan URL + params + forms
    2. Jalankan modul scan secara paralel
    3. Kumpulkan findings
    4. Simpan ke database
    """

    def __init__(self, config: ScanConfig, db):
        self.config = config
        self.db = db

    async def run(self) -> int:
        """Jalankan scan penuh, return scan_id."""
        config = self.config

        async with AsyncHTTPClient(
            base_headers=config.get_headers(),
            timeout=config.timeout,
            delay=config.delay,
            verify_ssl=False,
        ) as http:

            # ── Phase 1: Crawl ────────────────────────────────────────────────
            print("[*] Memulai crawl...")
            crawler = Crawler(config, http)
            crawled: List[CrawledURL] = await crawler.crawl()

            print(f"[+] {len(crawled)} URL ditemukan")

            if not crawled:
                print("[-] Crawler tidak menemukan URL. Kemungkinan:")
                print("    • Target memblokir bot (WAF/Cloudflare)")
                print("    • Coba tambahkan --cookie atau --header")
                print("    • Situs butuh JS rendering (playwright)")
                # Tetap lanjutkan dengan hanya target utama
                from core.crawler import CrawledURL as CU
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(config.target_url)
                params = list(parse_qs(parsed.query).keys())
                crawled = [CU(
                    url=config.target_url,
                    status=200,
                    params=params,
                    forms=[],
                    depth=0,
                )]
                print(f"[*] Melanjutkan scan hanya pada target URL: {config.target_url}")

            # ── Phase 2: Jalankan modul scan ──────────────────────────────────
            all_findings: List[Finding] = []
            modules_to_run = [m for m in config.modules if m in MODULE_MAP]

            print(f"[*] Menjalankan {len(modules_to_run)} modul: {', '.join(modules_to_run)}")

            async def run_module(module_name: str) -> List[Finding]:
                try:
                    mod = importlib.import_module(MODULE_MAP[module_name])
                    findings = await mod.scan(config, http, crawled)
                    if findings:
                        print(f"[!] {module_name.upper()}: {len(findings)} temuan")
                    else:
                        print(f"[✓] {module_name.upper()}: tidak ada temuan")
                    return findings
                except ImportError as e:
                    logger.warning("Modul %s tidak tersedia: %s", module_name, e)
                    return []
                except Exception as e:
                    logger.error("Error pada modul %s: %s", module_name, e, exc_info=True)
                    return []

            tasks = [run_module(m) for m in modules_to_run]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, list):
                    all_findings.extend(r)

            # ── Phase 3: Simpan hasil ─────────────────────────────────────────
            scan_id = self.db.create_scan(
                target=config.target_url,
                config={
                    "modules": ",".join(config.modules),
                    "depth": config.crawl_depth,
                    "threads": config.max_threads,
                },
            )
            for finding in all_findings:
                try:
                    self.db.save_finding(scan_id, finding)
                except Exception as e:
                    logger.warning("Gagal simpan finding: %s", e)

            self.db.finish_scan(scan_id, len(all_findings))

            print(f"\n{'─' * 60}")
            print(f"[+] Total temuan: {len(all_findings)}")

            # Summary per severity
            severity_count: Dict[str, int] = {}
            for f in all_findings:
                severity_count[f.severity] = severity_count.get(f.severity, 0) + 1

            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev in severity_count:
                    print(f"    {sev}: {severity_count[sev]}")

            return scan_id
