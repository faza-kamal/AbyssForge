"""
AbyssForge - CSRF Scanner
Deteksi Cross-Site Request Forgery: missing tokens, SameSite issues, unsafe forms.
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

logger = logging.getLogger(__name__)
MODULE_NAME = "csrf"

# Token names yang biasa digunakan sebagai CSRF protection
CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "_csrf", "csrf_token", "csrfmiddlewaretoken",
    "authenticity_token", "_token", "xsrf", "xsrf_token", "__requestverificationtoken",
    "antiforgery", "_csrf_token", "csrf-token", "x-csrf-token",
]

# State-changing HTTP methods
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _has_csrf_token(form: dict) -> bool:
    """Periksa apakah form memiliki CSRF token."""
    inputs_lower = [i.lower() for i in form.get("inputs", [])]
    return any(
        any(token in inp for token in CSRF_TOKEN_NAMES)
        for inp in inputs_lower
    )


def _has_samesite_cookie(headers: dict, cookie_name_hint: str = "") -> bool:
    """Periksa apakah cookie memiliki atribut SameSite."""
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            if "samesite" in v.lower():
                return True
    return False


async def _check_form_csrf(
    http: AsyncHTTPClient,
    page: "CrawledURL",
) -> List[Finding]:
    """Periksa form POST yang tidak memiliki CSRF protection."""
    findings = []

    for form in page.forms:
        method = form.get("method", "GET").upper()
        if method not in UNSAFE_METHODS:
            continue  # GET forms tidak perlu CSRF token

        action = form.get("action", page.url)
        inputs = form.get("inputs", [])

        # Periksa keberadaan CSRF token
        if not _has_csrf_token(form):
            # Ambil response untuk periksa cookie
            try:
                resp = await http.get(page.url)
                has_samesite = _has_samesite_cookie(resp.headers)
            except Exception:
                has_samesite = False

            if has_samesite:
                # SameSite cookie adalah mitigasi parsial
                cvss = 4.3
                title = "Form POST Tanpa CSRF Token (Dilindungi SameSite Cookie)"
                confidence = "LOW"
            else:
                cvss = 8.8
                title = "Form POST Rentan CSRF (Tanpa Token & SameSite)"
                confidence = "HIGH"

            findings.append(Finding.from_cvss(
                cvss_score=cvss,
                title=title,
                vuln_type=MODULE_NAME,
                url=action,
                method=method,
                description=(
                    f"Form {method} pada '{action}' tidak memiliki CSRF token. "
                    "Penyerang dapat membuat halaman berbahaya yang memicu permintaan "
                    "atas nama pengguna yang terautentikasi tanpa sepengetahuan mereka."
                    + (" Cookie SameSite memberikan perlindungan parsial." if has_samesite else ""),
                ),
                evidence=(
                    f"Form action: {action} | Method: {method} | "
                    f"Inputs: {', '.join(inputs[:5])}"
                ),
                remediation=(
                    "Implementasikan CSRF token yang unik, unpredictable, dan terikat pada sesi. "
                    "Verifikasi token di setiap request state-changing. "
                    "Tambahkan SameSite=Strict atau SameSite=Lax pada session cookies."
                ),
                references="https://owasp.org/www-community/attacks/csrf",
                module=MODULE_NAME,
                confidence=confidence,
            ))

    return findings


async def _check_json_csrf(
    http: AsyncHTTPClient,
    url: str,
) -> List[Finding]:
    """Periksa apakah endpoint JSON menerima text/plain (CSRF via form encoding)."""
    findings = []
    try:
        # Test apakah endpoint menerima request dengan Content-Type: text/plain
        # (teknik CSRF untuk bypass JSON APIs)
        resp = await http.post(
            url,
            data='{"test": "csrf_probe"}',
            headers={"Content-Type": "text/plain"},
        )
        if resp.error:
            return []

        ct = resp.header("Content-Type", "")
        if resp.status < 400 and "application/json" in ct:
            findings.append(Finding.from_cvss(
                cvss_score=6.5,
                title="JSON API Menerima text/plain (Potensi CSRF)",
                vuln_type=MODULE_NAME,
                url=url,
                method="POST",
                description=(
                    "API JSON endpoint menerima request dengan Content-Type: text/plain. "
                    "Ini dapat memungkinkan CSRF attack melalui form HTML biasa "
                    "yang men-submit data JSON."
                ),
                evidence=f"Status: {resp.status}, Response CT: {ct}",
                remediation=(
                    "Validasi Content-Type header secara ketat. "
                    "Tolak request JSON yang tidak memiliki Content-Type: application/json. "
                    "Implementasikan CSRF token atau gunakan custom request headers."
                ),
                references="https://portswigger.net/web-security/csrf",
                module=MODULE_NAME,
                confidence="MEDIUM",
                false_positive_risk="MEDIUM",
            ))
    except Exception as exc:
        logger.debug("JSON CSRF check error pada %s: %s", url, exc)

    return findings


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """Entry point modul CSRF."""
    findings: List[Finding] = []
    tasks = []

    for page in crawled:
        if page.forms:
            tasks.append(_check_form_csrf(http, page))

        # Periksa endpoint yang mungkin menerima JSON
        if any(kw in page.url.lower() for kw in ["/api/", "/rest/", "/graphql"]):
            tasks.append(_check_json_csrf(http, page.url))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    return findings
