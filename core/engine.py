"""
AbyssForge - Scan Engine v2
"""

import asyncio
import logging
import importlib
import re
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from typing import List, Dict

from core.config import ScanConfig
from core.crawler import Crawler, CrawledURL
from core.http_client import AsyncHTTPClient
from core.finding import Finding

logger = logging.getLogger(__name__)

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

# Regex ambil semua href dengan query params dari HTML
_HREF_PARAM_RE = re.compile(
    r'href\s*=\s*["\']([^"\'#]*\?[^"\'#]+)["\']',
    re.IGNORECASE,
)
_NAME_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_RE = re.compile(r'<form([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_ATTR_RE = re.compile(r'(\w[\w-]*)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)


async def _smart_fallback(config: ScanConfig, http: AsyncHTTPClient) -> List[CrawledURL]:
    """
    Fallback ketika crawler gagal:
    1. Fetch halaman utama
    2. Ekstrak semua link yang punya query params
    3. Buat CrawledURL untuk setiap URL dengan params
    4. Ekstrak form dari halaman utama
    """
    target = config.target_url
    parsed_base = urlparse(target)
    base = f"{parsed_base.scheme}://{parsed_base.netloc}"

    print(f"[*] Smart fallback: fetch halaman utama untuk discover params...")

    resp = await http.get(target)
    if resp.error:
        print(f"[-] Gagal fetch {target}: {resp.error}")
        # Kembalikan minimal target URL
        return [CrawledURL(url=target, status=0, params=[], forms=[], body="")]

    print(f"[*] Halaman utama: HTTP {resp.status}, {len(resp.text)} chars")

    results: List[CrawledURL] = []
    seen_urls = set()

    # ── Halaman utama sendiri ──────────────────────────────────────────────────
    # Ekstrak forms dari halaman utama
    forms = []
    for attrs_str, body in _FORM_RE.findall(resp.text):
        attrs      = dict(_ATTR_RE.findall(attrs_str))
        raw_action = attrs.get("action", "") or target
        try:
            action = urljoin(target, raw_action)
        except Exception:
            action = target
        method = attrs.get("method", "GET").upper()
        inputs = _NAME_RE.findall(body)
        if inputs:
            forms.append({"action": action, "method": method, "inputs": inputs})

    params_main = list(parse_qs(parsed_base.query, keep_blank_values=True).keys())

    results.append(CrawledURL(
        url=resp.url, status=resp.status,
        params=params_main, forms=forms,
        body=resp.text, headers=resp.headers,
    ))
    seen_urls.add(resp.url)

    if forms:
        print(f"[+] Form ditemukan di halaman utama: {len(forms)} form, inputs: {[f['inputs'] for f in forms]}")

    # ── Discover semua URL dengan params dari link di halaman ─────────────────
    param_urls_found = 0
    for raw_href in _HREF_PARAM_RE.findall(resp.text):
        try:
            full_url = urljoin(target, raw_href)
            parsed   = urlparse(full_url)

            # Hanya same domain
            if parsed.netloc != parsed_base.netloc:
                continue

            clean_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, parsed.query, ""
            ))

            if clean_url in seen_urls:
                continue
            seen_urls.add(clean_url)

            params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
            if params:
                results.append(CrawledURL(
                    url=clean_url, status=200,
                    params=params, forms=[],
                    body="",  # Tidak fetch dulu, hemat request
                ))
                param_urls_found += 1
                logger.debug("[fallback] URL+params: %s → %s", clean_url, params)

        except Exception:
            continue

    if param_urls_found > 0:
        print(f"[+] {param_urls_found} URL dengan query params ditemukan dari halaman utama")

    return results


class ScanEngine:
    def __init__(self, config: ScanConfig, db):
        self.config = config
        self.db = db

    async def run(self) -> int:
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

            if crawled:
                print(f"[+] {len(crawled)} halaman di-crawl")
                # Hitung statistik
                pages_with_params = sum(1 for c in crawled if c.params)
                pages_with_forms  = sum(1 for c in crawled if c.forms)
                total_params = sum(len(c.params) for c in crawled)
                total_forms  = sum(len(c.forms) for c in crawled)
                print(f"[*] {pages_with_params} halaman dengan params ({total_params} params total)")
                print(f"[*] {pages_with_forms} halaman dengan form ({total_forms} forms total)")
            else:
                print(f"[!] Crawler gagal menemukan URL → menggunakan smart fallback")
                crawled = await _smart_fallback(config, http)
                print(f"[+] Fallback: {len(crawled)} target untuk di-scan")

            # Ringkasan sebelum scan
            total_injection_pts = sum(len(c.params) for c in crawled) + \
                                  sum(sum(len(f.get("inputs",[])) for f in c.forms) for c in crawled)
            print(f"[*] Total titik injeksi: {total_injection_pts}")
            print("-" * 60)

            # ── Phase 2: Jalankan modul ───────────────────────────────────────
            all_findings: List[Finding] = []
            modules_to_run = [m for m in config.modules if m in MODULE_MAP]

            print(f"[*] Menjalankan {len(modules_to_run)} modul: {', '.join(modules_to_run)}")

            async def run_module(module_name: str) -> List[Finding]:
                try:
                    mod = importlib.import_module(MODULE_MAP[module_name])
                    findings = await mod.scan(config, http, crawled)
                    cnt = len(findings)
                    if cnt:
                        print(f"[!] {module_name.upper()}: {cnt} temuan")
                    else:
                        print(f"[✓] {module_name.upper()}: tidak ada temuan")
                    return findings
                except ImportError as e:
                    logger.warning("Modul %s tidak tersedia: %s", module_name, e)
                    return []
                except Exception as e:
                    logger.error("Error modul %s: %s", module_name, e, exc_info=True)
                    return []

            results = await asyncio.gather(*[run_module(m) for m in modules_to_run])
            for r in results:
                if isinstance(r, list):
                    all_findings.extend(r)

            # ── Phase 3: Simpan ───────────────────────────────────────────────
            scan_id = self.db.create_scan(
                target=config.target_url,
                config={"modules": ",".join(config.modules), "depth": config.crawl_depth},
            )
            for finding in all_findings:
                try:
                    self.db.save_finding(scan_id, finding)
                except Exception as e:
                    logger.warning("Gagal simpan finding: %s", e)

            self.db.finish_scan(scan_id, len(all_findings))

            print(f"\n{'─' * 60}")
            print(f"[+] Total temuan: {len(all_findings)}")
            sev_count: Dict[str, int] = {}
            for f in all_findings:
                sev_count[f.severity] = sev_count.get(f.severity, 0) + 1
            for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
                if sev in sev_count:
                    print(f"    {sev}: {sev_count[sev]}")

            return scan_id
