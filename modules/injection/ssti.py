"""
AbyssForge - Server-Side Template Injection (SSTI) Scanner
Deteksi SSTI pada berbagai template engine: Jinja2, Twig, Freemarker, Velocity, Mako.
Hanya boleh import dari core dan utils.
"""

import asyncio
import logging
import re
from typing import List, Dict, Tuple

from core.config import ScanConfig
from core.finding import Finding
from core.http_client import AsyncHTTPClient
from core.crawler import CrawledURL
from utils.url_utils import inject_param

logger = logging.getLogger(__name__)
MODULE_NAME = "ssti"

# Payload dengan ekspektasi output deterministik
# Format: (payload, expected_output, engine_hint)
SSTI_PROBES: List[Tuple[str, str, str]] = [
    # Jinja2 / Python
    ("{{7*7}}", "49", "Jinja2/Python"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${7*7}", "49", "Freemarker/Java"),
    ("<%= 7*7 %>", "49", "ERB/Ruby"),
    ("#{7*7}", "49", "Ruby (Slim)"),
    ("*{7*7}", "49", "Spring/Java"),
    # Twig
    ("{{7*7}}", "49", "Twig/PHP"),
    # Smarty
    ("{7*7}", "49", "Smarty/PHP"),
    # Velocity
    ("#set($x=7*7)${x}", "49", "Velocity/Java"),
]


async def _test_ssti(
    http: AsyncHTTPClient,
    url: str,
    param: str,
    probes: List[Tuple[str, str, str]],
    method: str = "GET",
) -> List[Finding]:
    findings = []

    for payload, expected, engine in probes:
        try:
            if method.upper() == "GET":
                test_url = inject_param(url, param, payload)
                resp = await http.get(test_url)
            else:
                resp = await http.post(url, data={param: payload})

            if resp.error:
                continue

            if expected in resp.text:
                idx = resp.text.find(expected)
                snippet = resp.text[max(0, idx-60):idx+120].strip()

                findings.append(Finding.from_cvss(
                    cvss_score=9.8,
                    title=f"Server-Side Template Injection ({engine})",
                    vuln_type=MODULE_NAME,
                    url=test_url if method.upper() == "GET" else url,
                    parameter=param,
                    method=method,
                    description=(
                        f"Parameter rentan terhadap SSTI ({engine}). "
                        f"Payload `{payload}` menghasilkan output `{expected}`, "
                        "mengkonfirmasi eksekusi ekspresi template di server. "
                        "Ini dapat menyebabkan Remote Code Execution (RCE)."
                    ),
                    evidence=snippet,
                    payload=payload,
                    remediation=(
                        "Jangan pernah menyisipkan input pengguna langsung ke dalam template. "
                        "Gunakan sandboxing template engine. "
                        "Validasi dan encode semua input sebelum diproses."
                    ),
                    references="https://portswigger.net/web-security/server-side-template-injection",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))
                break  # Konfirmasi pertama cukup

        except Exception as exc:
            logger.debug("SSTI test error pada %s[%s]: %s", url, param, exc)

    return findings


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """Entry point modul SSTI."""
    findings: List[Finding] = []
    tasks = []

    for page in crawled:
        for param in page.params:
            tasks.append(_test_ssti(http, page.url, param, SSTI_PROBES, "GET"))

        for form in page.forms:
            for inp in form.get("inputs", []):
                tasks.append(_test_ssti(http, form["action"], inp, SSTI_PROBES, form["method"]))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    seen, unique = set(), []
    for f in findings:
        key = (f.url, f.parameter, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
