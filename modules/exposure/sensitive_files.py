"""
AbyssForge - Sensitive Files & Information Exposure Scanner
Deteksi: .env, backup files, error leaks, technology fingerprinting,
         source code disclosure, credentials in HTML, dan debug pages.
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
from utils.payload_loader import load_wordlist

logger = logging.getLogger(__name__)
MODULE_NAME = "exposure"

# ─── Path file sensitif yang umum ditemukan ───────────────────────────────────

SENSITIVE_PATHS = [
    # Environment & config
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/database.yml", "/settings.py", "/settings.local.py",
    "/wp-config.php", "/wp-config.php.bak",
    "/configuration.php",  # Joomla
    "/app/config/parameters.yml",  # Symfony

    # Backup & archive
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
    "/db.sql", "/database.sql", "/website.zip", "/www.zip",
    "/.git/config", "/.git/HEAD",
    "/.svn/entries",
    "/.DS_Store",

    # Debug & info pages
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/?XDEBUG_SESSION_START=1",
    "/server-status",       # Apache mod_status
    "/server-info",         # Apache mod_info
    "/_profiler",           # Symfony profiler
    "/actuator",            # Spring Boot actuator
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/__debug__/",          # Django debug toolbar

    # Credentials & keys
    "/id_rsa", "/id_dsa", "/.ssh/id_rsa",
    "/credentials.json", "/service-account.json",
    "/secrets.yml",

    # Logs
    "/error.log", "/access.log", "/debug.log", "/app.log",
    "/logs/error.log", "/log/error.log",

    # Admin & panels
    "/admin", "/admin/", "/administrator",
    "/phpmyadmin", "/pma", "/myadmin",
    "/wp-admin", "/wp-login.php",
    "/jenkins", "/jira", "/confluence",
    "/kibana", "/grafana", "/prometheus",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/api-docs", "/openapi.json", "/v1/api-docs",
]

# ─── Pattern untuk deteksi konten sensitif di body ────────────────────────────

SENSITIVE_CONTENT_PATTERNS = {
    "Database Password": re.compile(
        r'(?:DB_PASS|DATABASE_PASSWORD|db_password|mysql_pass)\s*[=:]\s*["\']?([^\s"\'<&]{3,})',
        re.IGNORECASE,
    ),
    "API Key": re.compile(
        r'(?:api_key|apikey|secret_key|access_token)\s*[=:]\s*["\']?([A-Za-z0-9/_\-+]{20,})',
        re.IGNORECASE,
    ),
    "AWS Credentials": re.compile(
        r'AKIA[0-9A-Z]{16}',
        re.IGNORECASE,
    ),
    "Private Key": re.compile(
        r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        re.IGNORECASE,
    ),
    "Email/Password Pair": re.compile(
        r'password\s*[=:]\s*["\']([^"\'<>\s]{4,})["\']',
        re.IGNORECASE,
    ),
    "JWT Token": re.compile(
        r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    ),
}

# Teknologi fingerprinting dari response headers & body
TECHNOLOGY_FINGERPRINTS = {
    "WordPress": [r"wp-content/", r"wp-includes/", r'name="generator" content="WordPress'],
    "Drupal":    [r"Drupal.settings", r"/sites/default/", r'name="generator" content="Drupal'],
    "Joomla":    [r"/media/jui/", r"Joomla!", r'name="generator" content="Joomla'],
    "Laravel":   [r"laravel_session", r"XSRF-TOKEN"],
    "Django":    [r"csrfmiddlewaretoken", r"django"],
    "Rails":     [r"authenticity_token", r"X-Rails-"],
    "ASP.NET":   [r"__VIEWSTATE", r"ASP.NET_SessionId"],
    "Spring":    [r"spring", r"Spring Framework"],
    "Express":   [r"X-Powered-By.*Express"],
    "Flask":     [r"Werkzeug", r"flask"],
}

# Error patterns yang mengekspos informasi internal
ERROR_LEAK_PATTERNS = {
    "Stack Trace": re.compile(r'(?:Traceback|at .+\.java:\d+|Exception in thread)', re.IGNORECASE),
    "SQL Error":   re.compile(r'(?:ORA-\d+|mysql_fetch|pg_query|SQLiteException)', re.IGNORECASE),
    "PHP Error":   re.compile(r'(?:Parse error|Fatal error|Warning:.*in .*\.php)', re.IGNORECASE),
    "Debug Info":  re.compile(r'(?:DEBUG.*True|debug=true|\[DEBUG\])', re.IGNORECASE),
}


def _check_sensitive_content(body: str, url: str) -> List[Finding]:
    """Periksa body response untuk konten sensitif."""
    findings = []
    for label, pattern in SENSITIVE_CONTENT_PATTERNS.items():
        m = pattern.search(body)
        if m:
            snippet = body[max(0, m.start()-30):m.end()+100].strip()
            findings.append(Finding.from_cvss(
                cvss_score=8.2,
                title=f"Kredensial/Rahasia Terekspos: {label}",
                vuln_type=MODULE_NAME,
                url=url,
                description=(
                    f"{label} ditemukan terekspos dalam response. "
                    "Data sensitif ini dapat digunakan untuk akses tidak sah."
                ),
                evidence=snippet[:300],
                remediation=(
                    "Pindahkan semua rahasia ke variabel lingkungan atau secret manager. "
                    "Jangan commit credentials ke repository. "
                    "Rotasi semua credentials yang terekspos segera."
                ),
                references="https://owasp.org/www-project-top-ten/",
                module=MODULE_NAME,
                confidence="HIGH",
            ))
    return findings


def _fingerprint_technology(body: str, headers: dict, url: str) -> List[Finding]:
    """Identifikasi teknologi dari response."""
    findings = []
    detected = []

    for tech, patterns in TECHNOLOGY_FINGERPRINTS.items():
        combined = body + " " + " ".join(headers.values())
        if any(re.search(p, combined, re.IGNORECASE) for p in patterns):
            detected.append(tech)

    if detected:
        # Periksa versi dari header Generator atau X-Powered-By
        version_info = []
        for k, v in headers.items():
            if k.lower() in ("x-powered-by", "server", "x-generator"):
                version_info.append(f"{k}: {v}")

        generator_m = re.search(
            r'<meta name="generator" content="([^"]+)"', body, re.IGNORECASE
        )
        if generator_m:
            version_info.append(f"Generator: {generator_m.group(1)}")

        findings.append(Finding.from_cvss(
            cvss_score=3.7,
            title=f"Technology Fingerprint: {', '.join(detected)}",
            vuln_type=MODULE_NAME,
            url=url,
            description=(
                f"Teknologi yang digunakan teridentifikasi: {', '.join(detected)}. "
                "Informasi ini membantu attacker menargetkan kerentanan spesifik."
            ),
            evidence="; ".join(version_info) if version_info else f"Detected: {', '.join(detected)}",
            remediation=(
                "Sembunyikan versi software dari header dan meta tag. "
                "Pastikan semua komponen selalu diperbarui ke versi terbaru."
            ),
            references="https://owasp.org/www-project-web-security-testing-guide/",
            module=MODULE_NAME,
            confidence="HIGH",
        ))

    return findings


def _check_error_leaks(body: str, url: str) -> List[Finding]:
    """Periksa apakah error message mengekspos informasi internal."""
    findings = []
    for label, pattern in ERROR_LEAK_PATTERNS.items():
        m = pattern.search(body)
        if m:
            snippet = body[max(0, m.start()-20):m.end()+200].strip()
            findings.append(Finding.from_cvss(
                cvss_score=5.3,
                title=f"Error Message Leak: {label}",
                vuln_type=MODULE_NAME,
                url=url,
                description=(
                    f"{label} terekspos dalam response. "
                    "Pesan error internal mengungkap informasi tentang stack teknologi, "
                    "path file, atau struktur database."
                ),
                evidence=snippet[:400],
                remediation=(
                    "Matikan debug mode di production. "
                    "Tampilkan pesan error generik ke pengguna. "
                    "Log detail error hanya di server-side."
                ),
                references="https://owasp.org/www-project-web-security-testing-guide/",
                module=MODULE_NAME,
                confidence="HIGH",
            ))
    return findings


async def _check_sensitive_file(
    http: AsyncHTTPClient,
    base_url: str,
    path: str,
) -> List[Finding]:
    """Periksa satu path file sensitif."""
    findings = []
    parsed = urlparse(base_url)
    url = f"{parsed.scheme}://{parsed.netloc}{path}"

    try:
        resp = await http.get(url)
        if resp.error or resp.status not in (200, 206):
            return []

        body = resp.text
        ct = resp.header("Content-Type", "").lower()

        # Deteksi berdasarkan path
        if ".git" in path:
            if "ref:" in body or "[core]" in body:
                findings.append(Finding.from_cvss(
                    cvss_score=9.1,
                    title="Git Repository Terekspos",
                    vuln_type=MODULE_NAME,
                    url=url,
                    description=(
                        "File Git repository dapat diakses publik. "
                        "Attacker dapat mengunduh seluruh source code, "
                        "termasuk history commit dan data sensitif."
                    ),
                    evidence=body[:300].strip(),
                    remediation="Blokir akses ke direktori .git/ melalui konfigurasi web server.",
                    references="https://owasp.org/www-community/attacks/Sensitive_Data_Exposure",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))

        elif path == "/.env" or ".env" in path:
            if any(k in body for k in ["DB_", "APP_KEY", "SECRET", "PASSWORD", "TOKEN"]):
                findings.append(Finding.from_cvss(
                    cvss_score=9.8,
                    title="File .env Terekspos",
                    vuln_type=MODULE_NAME,
                    url=url,
                    description=(
                        "File .env yang mengandung konfigurasi aplikasi sensitif dapat diakses publik. "
                        "Berpotensi mengekspos credentials database, API keys, dan secret keys."
                    ),
                    evidence=body[:500].strip(),
                    remediation=(
                        "Pindahkan file .env ke luar web root. "
                        "Blokir akses ke file .env di web server. "
                        "Rotasi semua credentials yang terekspos."
                    ),
                    references="https://owasp.org/www-project-top-ten/",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))

        elif "phpinfo" in path or resp.status == 200 and "PHP Version" in body:
            findings.append(Finding.from_cvss(
                cvss_score=5.3,
                title="phpinfo() Terekspos",
                vuln_type=MODULE_NAME,
                url=url,
                description=(
                    "Halaman phpinfo() terekspos ke publik. "
                    "Mengungkap konfigurasi PHP, variabel environment, "
                    "path server, dan informasi sensitif lainnya."
                ),
                evidence="PHP Version detected in response.",
                remediation="Hapus file phpinfo() dari production server.",
                references="https://owasp.org/www-project-web-security-testing-guide/",
                module=MODULE_NAME,
                confidence="HIGH",
            ))

        elif "actuator" in path:
            findings.append(Finding.from_cvss(
                cvss_score=7.5,
                title="Spring Boot Actuator Terekspos",
                vuln_type=MODULE_NAME,
                url=url,
                description=(
                    "Spring Boot Actuator endpoint dapat diakses tanpa autentikasi. "
                    "Mengekspos informasi environment, konfigurasi, dan potentially RCE via /actuator/env."
                ),
                evidence=body[:300].strip(),
                remediation=(
                    "Batasi akses Actuator endpoints. "
                    "Nonaktifkan endpoint yang tidak diperlukan. "
                    "Aktifkan autentikasi untuk semua Actuator endpoints."
                ),
                references="https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
                module=MODULE_NAME,
                confidence="HIGH",
            ))

        elif resp.status == 200 and len(body) > 0:
            # Generic sensitive file detected
            content_check = _check_sensitive_content(body, url)
            error_check   = _check_error_leaks(body, url)
            findings.extend(content_check)
            findings.extend(error_check)

            if not content_check and not error_check and any(
                ext in path for ext in [".sql", ".bak", ".backup", ".zip", ".tar"]
            ):
                findings.append(Finding.from_cvss(
                    cvss_score=7.5,
                    title=f"File Sensitif Terekspos: {path}",
                    vuln_type=MODULE_NAME,
                    url=url,
                    description=f"File sensitif '{path}' dapat diakses secara publik.",
                    evidence=f"HTTP {resp.status}, Content-Length: {len(body)}",
                    remediation="Pindahkan file backup/sensitif ke luar web root atau batasi aksesnya.",
                    references="https://owasp.org/www-community/attacks/Sensitive_Data_Exposure",
                    module=MODULE_NAME,
                    confidence="MEDIUM",
                ))

    except Exception as exc:
        logger.debug("Sensitive file check error pada %s: %s", url, exc)

    return findings



async def _analyze_page_content(
    http: AsyncHTTPClient,
    url: str,
) -> List[Finding]:
    """Re-fetch halaman untuk analisis konten sensitif."""
    findings = []
    try:
        resp = await http.get(url)
        if resp.error or not resp.text:
            return []
        body = resp.text
        headers = resp.headers
        findings.extend(_check_sensitive_content(body, url))
        findings.extend(_check_error_leaks(body, url))
        findings.extend(_fingerprint_technology(body, headers, url))
    except Exception as exc:
        logger.debug("Analisis konten gagal untuk %s: %s", url, exc)
    return findings


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """Entry point modul exposure."""
    findings: List[Finding] = []
    tasks = []

    # Ambil wordlist tambahan jika tersedia
    extra_paths = load_wordlist("sensitive_paths")
    all_paths = list(set(SENSITIVE_PATHS + extra_paths))

    # Periksa file sensitif hanya sekali per domain
    checked_bases: set = set()

    for page in crawled:
        parsed = urlparse(page.url)
        base_key = f"{parsed.scheme}://{parsed.netloc}"

        if base_key not in checked_bases:
            checked_bases.add(base_key)
            for path in all_paths:
                tasks.append(_check_sensitive_file(http, page.url, path))

        # Periksa konten halaman yang sudah di-crawl (re-fetch)
        tasks.append(_analyze_page_content(http, page.url))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    # Deduplikasi
    seen, unique = set(), []
    for f in findings:
        key = (f.url, f.title[:60])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
