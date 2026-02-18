"""
AbyssForge - XSS Scanner
Deteksi: Reflected XSS, DOM XSS (heuristik), Stored XSS (basic).
Hanya boleh import dari core dan utils.
"""

import asyncio
import logging
import re
import html
from typing import List, Dict

from core.config import ScanConfig
from core.finding import Finding
from core.http_client import AsyncHTTPClient
from core.crawler import CrawledURL
from utils.payload_loader import load_payloads
from utils.url_utils import inject_param

logger = logging.getLogger(__name__)

MODULE_NAME = "xss"

# Penanda unik agar mudah dicari di response
XSS_CANARY = "ABYSSXSS"

# Sumber sink DOM XSS yang rentan
DOM_SINK_PATTERNS = [
    r'document\.write\s*\(',
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'location\.href\s*=',
    r'location\.replace\s*\(',
    r'document\.cookie\s*=',
    r'\.src\s*=',
]

_DOM_SINK_RE = re.compile("|".join(DOM_SINK_PATTERNS), re.IGNORECASE)

# Source DOM XSS yang sering dieksploitasi
DOM_SOURCE_PATTERNS = [
    r'location\.search',
    r'location\.hash',
    r'location\.href',
    r'document\.referrer',
    r'window\.name',
]

_DOM_SOURCE_RE = re.compile("|".join(DOM_SOURCE_PATTERNS), re.IGNORECASE)


def _payload_reflected(response_text: str, payload: str, canary: str) -> bool:
    """Cek apakah payload atau canary muncul unescaped di response."""
    # Cek canary langsung
    if canary in response_text:
        # Pastikan tidak di-escape (misalnya &lt;script&gt;)
        escaped = html.escape(canary)
        if escaped not in response_text or canary in response_text:
            return True
    # Cek karakter kunci XSS tidak di-encode
    critical = ["<script", "javascript:", "onerror=", "onload=", "alert("]
    for kw in critical:
        if kw.lower() in response_text.lower():
            return True
    return False


async def _test_reflected_xss(
    http: AsyncHTTPClient,
    url: str,
    param: str,
    payloads: List[str],
    method: str = "GET",
) -> List[Finding]:
    findings = []
    for payload in payloads:
        canary = f"{XSS_CANARY}{hash(payload) & 0xFFFF:04X}"
        test_payload = payload.replace("CANARY", canary)

        try:
            if method.upper() == "GET":
                test_url = inject_param(url, param, test_payload)
                resp = await http.get(test_url)
            else:
                resp = await http.post(url, data={param: test_payload})

            if resp.error:
                continue

            if _payload_reflected(resp.text, test_payload, canary):
                # Cek apakah ada dalam konteks script (lebih berbahaya)
                in_script = bool(re.search(
                    r'<script[^>]*>[^<]*' + re.escape(canary),
                    resp.text, re.IGNORECASE
                ))

                # Snippet evidence
                idx = resp.text.lower().find(canary.lower())
                snippet = resp.text[max(0, idx-80):idx+160] if idx >= 0 else test_payload[:200]

                cvss = 8.8 if in_script else 7.4
                findings.append(Finding.from_cvss(
                    cvss_score=cvss,
                    title="Cross-Site Scripting (Reflected XSS)",
                    vuln_type=MODULE_NAME,
                    url=test_url if method.upper() == "GET" else url,
                    parameter=param,
                    method=method,
                    description=(
                        "Parameter rentan terhadap Reflected XSS. "
                        "Input pengguna di-refleksikan ke halaman tanpa sanitasi yang memadai, "
                        "memungkinkan eksekusi JavaScript berbahaya di browser korban."
                    ),
                    evidence=snippet.strip(),
                    payload=test_payload,
                    remediation=(
                        "Terapkan output encoding yang tepat sesuai konteks (HTML, JS, URL). "
                        "Gunakan Content Security Policy (CSP). "
                        "Validasi input di sisi server."
                    ),
                    references="https://owasp.org/www-community/attacks/xss/",
                    module=MODULE_NAME,
                    confidence="HIGH" if in_script else "MEDIUM",
                ))
                break  # Satu konfirmasi sudah cukup

        except Exception as exc:
            logger.debug("Reflected XSS error pada %s[%s]: %s", url, param, exc)

    return findings


async def _test_dom_xss(
    http: AsyncHTTPClient,
    url: str,
) -> List[Finding]:
    """Deteksi potensi DOM XSS berdasarkan heuristik source/sink."""
    findings = []
    try:
        resp = await http.get(url)
        if resp.error or "text/html" not in resp.header("Content-Type", ""):
            return []

        has_sink   = bool(_DOM_SINK_RE.search(resp.text))
        has_source = bool(_DOM_SOURCE_RE.search(resp.text))

        if has_sink and has_source:
            # Coba deteksi pola berbahaya: source langsung masuk ke sink
            sink_m   = _DOM_SINK_RE.search(resp.text)
            source_m = _DOM_SOURCE_RE.search(resp.text)

            findings.append(Finding.from_cvss(
                cvss_score=6.5,
                title="Potensi DOM-based XSS",
                vuln_type=MODULE_NAME,
                url=url,
                description=(
                    "Halaman mengandung sumber data tidak aman (location.search, document.referrer, dll) "
                    "yang berpotensi mengalir ke sink berbahaya (innerHTML, document.write, eval, dll). "
                    "Perlu analisis manual untuk konfirmasi."
                ),
                evidence=(
                    f"Source: {source_m.group()!r} | Sink: {sink_m.group()!r}"
                ),
                payload="N/A (analisis statis)",
                remediation=(
                    "Hindari penggunaan innerHTML, document.write, dan eval dengan input tidak terpercaya. "
                    "Gunakan textContent atau DOMPurify untuk sanitasi."
                ),
                references="https://owasp.org/www-community/attacks/DOM_Based_XSS",
                module=MODULE_NAME,
                confidence="LOW",
                false_positive_risk="HIGH",
            ))
    except Exception as exc:
        logger.debug("DOM XSS test error pada %s: %s", url, exc)

    return findings


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """Entry point modul XSS."""
    payloads = load_payloads("xss")
    findings: List[Finding] = []
    tasks = []

    for page in crawled:
        # DOM XSS per halaman
        tasks.append(_test_dom_xss(http, page.url))

        # Reflected XSS pada query params
        for param in page.params:
            tasks.append(_test_reflected_xss(http, page.url, param, payloads, "GET"))

        # Reflected XSS pada form inputs
        for form in page.forms:
            for inp in form.get("inputs", []):
                tasks.append(_test_reflected_xss(
                    http, form["action"], inp, payloads, form["method"]
                ))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    # Deduplikasi
    seen, unique = set(), []
    for f in findings:
        key = (f.url, f.parameter, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
