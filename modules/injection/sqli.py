"""
AbyssForge - SQL Injection Scanner
Deteksi: Error-based, Blind boolean-based, Time-based blind.
Hanya boleh import dari core dan utils.
"""

import asyncio
import logging
import time
import re
from typing import List, Dict
from urllib.parse import urlparse

from core.config import ScanConfig
from core.finding import Finding
from core.http_client import AsyncHTTPClient
from core.crawler import CrawledURL
from utils.payload_loader import load_payloads
from utils.url_utils import inject_param

logger = logging.getLogger(__name__)

MODULE_NAME = "sqli"

# ─── Error signatures (Error-based SQLi) ──────────────────────────────────────
SQL_ERRORS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch_array\(\)",
    r"unclosed quotation mark",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"postgresql.*error",
    # MSSQL
    r"microsoft sql server",
    r"odbc sql server driver",
    r"unclosed quotation mark after the character string",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    r"quoted string not properly terminated",
    # SQLite
    r"sqlite_exception",
    r"sqlite3\.operationalerror",
    # Generic
    r"sql syntax.*mysql",
    r"syntax error.*sql",
    r"division by zero in",
    r"invalid query",
    r"supplied argument is not a valid mysql",
]

_SQL_ERROR_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)

# Time-based delay threshold (detik)
TIME_THRESHOLD = 4.0


async def _test_error_sqli(
    http: AsyncHTTPClient,
    url: str,
    param: str,
    payloads: List[str],
    method: str = "GET",
) -> List[Finding]:
    """Uji error-based SQLi pada satu parameter."""
    findings = []
    for payload in payloads:
        try:
            if method.upper() == "GET":
                test_url = inject_param(url, param, payload)
                resp = await http.get(test_url)
            else:
                resp = await http.post(url, data={param: payload})

            if resp.error:
                continue

            if _SQL_ERROR_RE.search(resp.text):
                snippet = _extract_snippet(resp.text, _SQL_ERROR_RE)
                findings.append(Finding.from_cvss(
                    cvss_score=9.1,
                    title="SQL Injection (Error-based)",
                    vuln_type=MODULE_NAME,
                    url=test_url if method.upper() == "GET" else url,
                    parameter=param,
                    method=method,
                    description=(
                        "Parameter rentan terhadap SQL Injection error-based. "
                        "Attacker dapat mengekstrak data dari database."
                    ),
                    evidence=snippet,
                    payload=payload,
                    remediation=(
                        "Gunakan prepared statements / parameterized queries. "
                        "Jangan tampilkan pesan error SQL ke pengguna."
                    ),
                    references="https://owasp.org/www-community/attacks/SQL_Injection",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))
                break  # Satu konfirmasi sudah cukup untuk parameter ini

        except Exception as exc:
            logger.debug("Error-based test error pada %s[%s]: %s", url, param, exc)

    return findings


async def _test_time_sqli(
    http: AsyncHTTPClient,
    url: str,
    param: str,
    payloads: List[str],
    method: str = "GET",
) -> List[Finding]:
    """Uji time-based blind SQLi."""
    findings = []
    for payload in payloads:
        try:
            t0 = time.monotonic()
            if method.upper() == "GET":
                test_url = inject_param(url, param, payload)
                resp = await http.get(test_url)
            else:
                resp = await http.post(url, data={param: payload})

            elapsed = time.monotonic() - t0

            if resp.error:
                continue

            if elapsed >= TIME_THRESHOLD:
                findings.append(Finding.from_cvss(
                    cvss_score=8.5,
                    title="SQL Injection (Time-based Blind)",
                    vuln_type=MODULE_NAME,
                    url=test_url if method.upper() == "GET" else url,
                    parameter=param,
                    method=method,
                    description=(
                        f"Parameter rentan terhadap Time-based Blind SQLi. "
                        f"Response delay {elapsed:.1f}s terdeteksi dengan payload sleep."
                    ),
                    evidence=f"Delay: {elapsed:.1f}s (threshold: {TIME_THRESHOLD}s)",
                    payload=payload,
                    remediation="Gunakan prepared statements. Batasi waktu query di database.",
                    references="https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                    module=MODULE_NAME,
                    confidence="MEDIUM",
                ))
                break
        except Exception as exc:
            logger.debug("Time-based test error pada %s[%s]: %s", url, param, exc)

    return findings


async def _test_boolean_sqli(
    http: AsyncHTTPClient,
    url: str,
    param: str,
    original_resp_len: int,
    method: str = "GET",
) -> List[Finding]:
    """Uji boolean-based blind SQLi (true vs false)."""
    true_payload  = "' OR '1'='1"
    false_payload = "' OR '1'='2"

    try:
        if method.upper() == "GET":
            resp_true  = await http.get(inject_param(url, param, true_payload))
            resp_false = await http.get(inject_param(url, param, false_payload))
        else:
            resp_true  = await http.post(url, data={param: true_payload})
            resp_false = await http.post(url, data={param: false_payload})

        if resp_true.error or resp_false.error:
            return []

        len_true  = len(resp_true.text)
        len_false = len(resp_false.text)
        len_diff  = abs(len_true - len_false)

        # Perbedaan signifikan antara true/false → indikasi boolean-based
        if len_diff > 50 and abs(len_true - original_resp_len) < abs(len_false - original_resp_len):
            return [Finding.from_cvss(
                cvss_score=8.0,
                title="SQL Injection (Boolean-based Blind)",
                vuln_type=MODULE_NAME,
                url=url,
                parameter=param,
                method=method,
                description=(
                    "Parameter mungkin rentan terhadap Boolean-based Blind SQLi. "
                    f"Perbedaan panjang response: {len_diff} byte antara kondisi TRUE dan FALSE."
                ),
                evidence=f"TRUE response: {len_true}B | FALSE response: {len_false}B | diff: {len_diff}B",
                payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                remediation="Gunakan prepared statements dan ORM yang aman.",
                references="https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                module=MODULE_NAME,
                confidence="MEDIUM",
                false_positive_risk="MEDIUM",
            )]
    except Exception as exc:
        logger.debug("Boolean test error pada %s[%s]: %s", url, param, exc)

    return []


def _extract_snippet(text: str, pattern: re.Pattern, window: int = 200) -> str:
    """Ekstrak snippet teks di sekitar pattern yang cocok."""
    m = pattern.search(text)
    if not m:
        return ""
    start = max(0, m.start() - 50)
    end = min(len(text), m.end() + window)
    return text[start:end].strip()


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """
    Entry point modul SQLi.
    Dipanggil oleh ScanEngine dengan interface standar.
    """
    error_payloads = load_payloads("sqli_error")
    time_payloads  = load_payloads("sqli_time")
    findings: List[Finding] = []
    tasks = []

    for page in crawled:
        # Kumpulkan semua titik injeksi: query params + form inputs
        injection_points: List[Dict] = []

        for param in page.params:
            injection_points.append({"url": page.url, "param": param, "method": "GET"})

        for form in page.forms:
            for inp in form.get("inputs", []):
                injection_points.append({
                    "url": form["action"],
                    "param": inp,
                    "method": form["method"],
                })

        for point in injection_points:
            url    = point["url"]
            param  = point["param"]
            method = point["method"]

            # Baseline response length untuk boolean test
            try:
                baseline = await http.get(url)
                baseline_len = len(baseline.text) if not baseline.error else 0
            except Exception:
                baseline_len = 0

            tasks.append(_test_error_sqli(http, url, param, error_payloads, method))
            tasks.append(_test_time_sqli(http, url, param, time_payloads, method))
            tasks.append(_test_boolean_sqli(http, url, param, baseline_len, method))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)
        elif isinstance(r, Exception):
            logger.debug("SQLi task error: %s", r)

    # Deduplikasi berdasarkan url+param+judul
    seen = set()
    unique = []
    for f in findings:
        key = (f.url, f.parameter, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
