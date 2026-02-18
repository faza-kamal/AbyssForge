"""
AbyssForge - Security Headers & Misconfiguration Scanner
Deteksi: Missing security headers, CORS misconfiguration, directory listing,
         path traversal, SSL/TLS issues, server disclosure.
Hanya boleh import dari core dan utils.
"""

import asyncio
import logging
import re
import ssl
import socket
from typing import List, Optional
from urllib.parse import urlparse

from core.config import ScanConfig
from core.finding import Finding
from core.http_client import AsyncHTTPClient
from core.crawler import CrawledURL

logger = logging.getLogger(__name__)
MODULE_NAME = "misconfig"

# ─── Security Headers yang Wajib Ada ─────────────────────────────────────────

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "cvss": 7.4,
        "description": "HTTP Strict Transport Security (HSTS) tidak dikonfigurasi. Browser dapat terhubung via HTTP yang tidak aman.",
        "remediation": "Tambahkan: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "cvss": 6.1,
        "description": "Content Security Policy (CSP) tidak dikonfigurasi. Ini meningkatkan risiko XSS.",
        "remediation": "Definisikan CSP yang ketat: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "cvss": 4.3,
        "description": "Header X-Content-Type-Options tidak ada. Browser dapat melakukan MIME-type sniffing.",
        "remediation": "Tambahkan: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "cvss": 6.5,
        "description": "Header X-Frame-Options tidak ada. Halaman rentan terhadap serangan Clickjacking.",
        "remediation": "Tambahkan: X-Frame-Options: DENY atau SAMEORIGIN",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "cvss": 3.7,
        "description": "Header Referrer-Policy tidak ada. URL sensitif dapat bocor ke pihak ketiga.",
        "remediation": "Tambahkan: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "cvss": 3.1,
        "description": "Header Permissions-Policy tidak ada. Fitur browser berbahaya (kamera, mikrofon) tidak dibatasi.",
        "remediation": "Tambahkan: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

# Header yang tidak boleh ada (information disclosure)
DANGEROUS_HEADERS = {
    "Server": "Mengungkap versi server web (information disclosure).",
    "X-Powered-By": "Mengungkap teknologi backend (PHP, ASP.NET, Express, dll).",
    "X-AspNet-Version": "Mengungkap versi ASP.NET yang digunakan.",
    "X-AspNetMvc-Version": "Mengungkap versi ASP.NET MVC.",
}

# Directory listing indicators
DIR_LISTING_INDICATORS = [
    "index of /",
    "directory listing for",
    "parent directory",
    "[to parent directory]",
    "apache/",
    "nginx/",
]

# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/%252e%252e%252f" * 3 + "etc/passwd",
    "/....//....//....//etc/passwd",
]

PATH_TRAVERSAL_INDICATORS = [
    r"root:.*:0:0:",
    r"\[boot loader\]",
    r"nobody:x:",
    r"daemon:x:",
]
_PT_RE = re.compile("|".join(PATH_TRAVERSAL_INDICATORS), re.IGNORECASE)


async def _check_security_headers(
    http: AsyncHTTPClient,
    url: str,
) -> List[Finding]:
    """Periksa keberadaan dan konfigurasi security headers."""
    findings = []
    try:
        resp = await http.get(url)
        if resp.error:
            return []

        # Missing headers
        for header_name, meta in REQUIRED_HEADERS.items():
            if not resp.header(header_name):
                findings.append(Finding.from_cvss(
                    cvss_score=meta["cvss"],
                    title=f"Header Keamanan Hilang: {header_name}",
                    vuln_type=MODULE_NAME,
                    url=url,
                    description=meta["description"],
                    evidence=f"Header '{header_name}' tidak ditemukan dalam response.",
                    remediation=meta["remediation"],
                    references="https://owasp.org/www-project-secure-headers/",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))

        # Dangerous headers
        for header_name, description in DANGEROUS_HEADERS.items():
            value = resp.header(header_name)
            if value:
                findings.append(Finding.from_cvss(
                    cvss_score=4.3,
                    title=f"Information Disclosure via Header: {header_name}",
                    vuln_type=MODULE_NAME,
                    url=url,
                    description=description,
                    evidence=f"{header_name}: {value}",
                    remediation=f"Hapus atau sembunyikan header '{header_name}' dari response.",
                    references="https://owasp.org/www-project-web-security-testing-guide/",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))

    except Exception as exc:
        logger.debug("Header check error pada %s: %s", url, exc)

    return findings


async def _check_cors(
    http: AsyncHTTPClient,
    url: str,
) -> List[Finding]:
    """Periksa konfigurasi CORS."""
    findings = []
    try:
        # Test dengan origin berbahaya
        evil_origin = "https://evil.attacker.com"
        resp = await http.get(url, headers={"Origin": evil_origin})
        if resp.error:
            return []

        acao = resp.header("Access-Control-Allow-Origin", "")
        acac = resp.header("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            findings.append(Finding.from_cvss(
                cvss_score=9.1,
                title="CORS Misconfiguration: Wildcard dengan Credentials",
                vuln_type=MODULE_NAME,
                url=url,
                description=(
                    "CORS dikonfigurasi dengan Access-Control-Allow-Origin: * DAN "
                    "Access-Control-Allow-Credentials: true secara bersamaan. "
                    "Ini memungkinkan situs berbahaya mengakses resource dengan kredensial pengguna."
                ),
                evidence=f"ACAO: {acao} | ACAC: {acac}",
                remediation=(
                    "Jangan gunakan wildcard (*) jika credentials diizinkan. "
                    "Whitelist origin spesifik yang diizinkan."
                ),
                references="https://portswigger.net/web-security/cors",
                module=MODULE_NAME,
                confidence="HIGH",
            ))
        elif acao == evil_origin:
            # Origin berbahaya direfleksikan
            if acac.lower() == "true":
                findings.append(Finding.from_cvss(
                    cvss_score=8.8,
                    title="CORS: Origin Arbitrer Diterima dengan Credentials",
                    vuln_type=MODULE_NAME,
                    url=url,
                    description=(
                        "Server merefleksikan Origin header sembarang dan mengizinkan credentials. "
                        "Attacker dapat melakukan cross-origin request dengan credentials korban."
                    ),
                    evidence=f"Request Origin: {evil_origin} → ACAO: {acao} | ACAC: {acac}",
                    remediation="Validasi Origin header secara ketat terhadap whitelist.",
                    references="https://portswigger.net/web-security/cors",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))
            else:
                findings.append(Finding.from_cvss(
                    cvss_score=5.4,
                    title="CORS: Origin Arbitrer Diterima (tanpa Credentials)",
                    vuln_type=MODULE_NAME,
                    url=url,
                    description="Server merefleksikan Origin header sembarang (tanpa credentials).",
                    evidence=f"Request Origin: {evil_origin} → ACAO: {acao}",
                    remediation="Validasi Origin header secara ketat terhadap whitelist.",
                    references="https://portswigger.net/web-security/cors",
                    module=MODULE_NAME,
                    confidence="MEDIUM",
                ))

    except Exception as exc:
        logger.debug("CORS check error pada %s: %s", url, exc)

    return findings


async def _check_directory_listing(
    http: AsyncHTTPClient,
    url: str,
    paths: Optional[List[str]] = None,
) -> List[Finding]:
    """Periksa apakah directory listing diaktifkan."""
    findings = []
    check_paths = paths or ["/", "/uploads/", "/files/", "/backup/", "/assets/", "/static/"]

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in check_paths:
        try:
            resp = await http.get(base + path)
            if resp.error:
                continue

            body_lower = resp.text.lower()
            if any(ind in body_lower for ind in DIR_LISTING_INDICATORS):
                findings.append(Finding.from_cvss(
                    cvss_score=5.3,
                    title=f"Directory Listing Aktif: {path}",
                    vuln_type=MODULE_NAME,
                    url=base + path,
                    description=(
                        f"Directory listing diaktifkan pada path '{path}'. "
                        "Penyerang dapat melihat daftar file dan direktori."
                    ),
                    evidence=resp.text[:500].strip(),
                    remediation=(
                        "Nonaktifkan directory listing di konfigurasi web server "
                        "(Options -Indexes untuk Apache, autoindex off untuk Nginx)."
                    ),
                    references="https://owasp.org/www-project-web-security-testing-guide/",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))

        except Exception as exc:
            logger.debug("Dir listing check error pada %s%s: %s", base, path, exc)

    return findings


async def _check_path_traversal(
    http: AsyncHTTPClient,
    url: str,
) -> List[Finding]:
    """Periksa kerentanan path traversal."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for payload in PATH_TRAVERSAL_PAYLOADS:
        test_url = base + payload
        try:
            resp = await http.get(test_url)
            if resp.error:
                continue

            if _PT_RE.search(resp.text):
                m = _PT_RE.search(resp.text)
                snippet = resp.text[max(0, m.start()-10):m.end()+100].strip()
                findings.append(Finding.from_cvss(
                    cvss_score=9.1,
                    title="Path Traversal / Directory Traversal",
                    vuln_type=MODULE_NAME,
                    url=test_url,
                    description=(
                        "Server rentan terhadap path traversal. "
                        "Attacker dapat membaca file sensitif di luar web root."
                    ),
                    evidence=snippet,
                    payload=payload,
                    remediation=(
                        "Validasi dan normalisasi semua path input. "
                        "Gunakan realpath() dan pastikan path berada di dalam direktori yang diizinkan. "
                        "Terapkan prinsip least privilege pada file system."
                    ),
                    references="https://owasp.org/www-community/attacks/Path_Traversal",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))
                break

        except Exception as exc:
            logger.debug("Path traversal test error pada %s: %s", test_url, exc)

    return findings


async def _check_ssl_tls(url: str) -> List[Finding]:
    """Periksa konfigurasi SSL/TLS dasar."""
    findings = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        findings.append(Finding.from_cvss(
            cvss_score=7.4,
            title="Site Tidak Menggunakan HTTPS",
            vuln_type=MODULE_NAME,
            url=url,
            description="Website menggunakan HTTP plain-text, rentan terhadap man-in-the-middle attack.",
            evidence=f"URL scheme: {parsed.scheme}",
            remediation="Migrasikan ke HTTPS dengan sertifikat TLS yang valid. Redirect semua HTTP ke HTTPS.",
            references="https://owasp.org/www-project-web-security-testing-guide/",
            module=MODULE_NAME,
            confidence="HIGH",
        ))
        return findings

    host = parsed.hostname
    port = parsed.port or 443

    try:
        # Coba koneksi TLS 1.0 (deprecated)
        ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_old.check_hostname = False
        ctx_old.verify_mode = ssl.CERT_NONE
        ctx_old.minimum_version = ssl.TLSVersion.TLSv1
        ctx_old.maximum_version = ssl.TLSVersion.TLSv1

        loop = asyncio.get_event_loop()

        def try_tls10():
            try:
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx_old.wrap_socket(sock, server_hostname=host):
                        return True
            except Exception:
                return False

        tls10_ok = await loop.run_in_executor(None, try_tls10)
        if tls10_ok:
            findings.append(Finding.from_cvss(
                cvss_score=6.5,
                title="TLS 1.0 Masih Didukung (Deprecated)",
                vuln_type=MODULE_NAME,
                url=url,
                description="Server mendukung TLS 1.0 yang sudah deprecated dan rentan (BEAST, POODLE).",
                evidence=f"Koneksi TLS 1.0 berhasil ke {host}:{port}",
                remediation="Nonaktifkan TLS 1.0 dan TLS 1.1. Gunakan minimal TLS 1.2, preferensi TLS 1.3.",
                references="https://tools.ietf.org/html/rfc8996",
                module=MODULE_NAME,
                confidence="HIGH",
            ))
    except Exception as exc:
        logger.debug("SSL/TLS check error: %s", exc)

    return findings


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """Entry point modul misconfiguration."""
    findings: List[Finding] = []
    tasks = []

    # Periksa hanya URL unik per domain untuk headers/CORS
    checked_bases: set = set()

    for page in crawled:
        parsed = urlparse(page.url)
        base_key = f"{parsed.scheme}://{parsed.netloc}"

        if base_key not in checked_bases:
            checked_bases.add(base_key)
            tasks.append(_check_security_headers(http, page.url))
            tasks.append(_check_cors(http, page.url))
            tasks.append(_check_directory_listing(http, page.url))
            tasks.append(_check_path_traversal(http, page.url))
            tasks.append(_check_ssl_tls(page.url))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    return findings
