"""
AbyssForge - Open Redirect Scanner
Deteksi Open Redirect pada parameter URL.
Hanya boleh import dari core dan utils.
"""

import asyncio
import logging
from typing import List
from urllib.parse import urlparse

from core.config import ScanConfig
from core.finding import Finding
from core.http_client import AsyncHTTPClient
from core.crawler import CrawledURL
from utils.url_utils import inject_param

logger = logging.getLogger(__name__)
MODULE_NAME = "redirect"

REDIRECT_PARAM_KEYWORDS = [
    "redirect", "redirect_to", "redirect_url", "redirecturl",
    "return", "return_url", "returnurl", "returnTo",
    "next", "next_url", "goto", "target", "dest", "destination",
    "url", "link", "continue", "out", "forward", "location",
    "go", "back", "checkout_url",
]

# Payload redirect ke domain berbahaya
REDIRECT_PAYLOADS = [
    "https://evil.attacker.com",
    "//evil.attacker.com",
    "https://evil.attacker.com/",
    "//evil.attacker.com",
    "https:evil.attacker.com",
    "%2F%2Fevil.attacker.com",
    "https%3A%2F%2Fevil.attacker.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

EVIL_DOMAIN = "evil.attacker.com"


def _is_redirect_param(param: str) -> bool:
    p = param.lower()
    return any(kw in p for kw in REDIRECT_PARAM_KEYWORDS)


async def _test_open_redirect(
    http: AsyncHTTPClient,
    url: str,
    param: str,
    method: str = "GET",
) -> List[Finding]:
    findings = []

    for payload in REDIRECT_PAYLOADS:
        try:
            if method.upper() == "GET":
                test_url = inject_param(url, param, payload)
                resp = await http.get(test_url)
            else:
                resp = await http.post(url, data={param: payload})

            if resp.error:
                continue

            # Cek apakah response adalah redirect ke domain berbahaya
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.header("Location", "")
                if EVIL_DOMAIN in location:
                    findings.append(Finding.from_cvss(
                        cvss_score=6.1,
                        title="Open Redirect",
                        vuln_type=MODULE_NAME,
                        url=test_url if method.upper() == "GET" else url,
                        parameter=param,
                        method=method,
                        description=(
                            f"Parameter '{param}' rentan terhadap Open Redirect. "
                            f"Server melakukan redirect ke: {location}. "
                            "Penyerang dapat menggunakannya untuk phishing atau bypass autentikasi."
                        ),
                        evidence=f"HTTP {resp.status} Location: {location}",
                        payload=payload,
                        remediation=(
                            "Validasi URL redirect terhadap whitelist domain yang diizinkan. "
                            "Jangan gunakan nilai URL langsung dari input pengguna sebagai tujuan redirect. "
                            "Gunakan identifier/mapping daripada URL langsung."
                        ),
                        references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        module=MODULE_NAME,
                        confidence="HIGH",
                    ))
                    return findings

            # Cek juga di body (meta refresh atau JavaScript redirect)
            if EVIL_DOMAIN in resp.text:
                import re
                meta_m = re.search(
                    rf'(?:meta.*refresh|window\.location|location\.href)\s*.*{re.escape(EVIL_DOMAIN)}',
                    resp.text, re.IGNORECASE
                )
                if meta_m:
                    findings.append(Finding.from_cvss(
                        cvss_score=5.4,
                        title="Open Redirect (via Meta/JS)",
                        vuln_type=MODULE_NAME,
                        url=test_url if method.upper() == "GET" else url,
                        parameter=param,
                        method=method,
                        description=(
                            f"Potensi Open Redirect via meta refresh atau JavaScript pada parameter '{param}'."
                        ),
                        evidence=meta_m.group()[:200],
                        payload=payload,
                        remediation="Validasi semua URL redirect. Jangan refleksikan URL user ke redirect.",
                        references="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        module=MODULE_NAME,
                        confidence="MEDIUM",
                    ))
                    return findings

        except Exception as exc:
            logger.debug("Open redirect test error pada %s[%s]: %s", url, param, exc)

    return findings


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """Entry point modul open redirect."""
    findings: List[Finding] = []
    tasks = []

    for page in crawled:
        for param in page.params:
            if _is_redirect_param(param):
                tasks.append(_test_open_redirect(http, page.url, param, "GET"))

        for form in page.forms:
            for inp in form.get("inputs", []):
                if _is_redirect_param(inp):
                    tasks.append(_test_open_redirect(http, form["action"], inp, form["method"]))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    seen, unique = set(), []
    for f in findings:
        key = (f.url, f.parameter)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
