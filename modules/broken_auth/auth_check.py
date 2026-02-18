"""
AbyssForge - Broken Authentication Scanner
Deteksi: Weak cookies, session fixation, brute force exposure, default credentials.
Hanya boleh import dari core dan utils.
"""

import asyncio
import base64
import logging
import re
from typing import List
from urllib.parse import urlparse

from core.config import ScanConfig
from core.finding import Finding
from core.http_client import AsyncHTTPClient
from core.crawler import CrawledURL

logger = logging.getLogger(__name__)
MODULE_NAME = "auth"

# Nama cookie yang sering mengindikasikan session token
SESSION_COOKIE_PATTERNS = [
    "session", "sess", "sessid", "sessionid",
    "token", "auth", "jwt", "sid",
    "phpsessid", "jsessionid", "aspsessionid", "aspnet_sessionid",
    "laravel_session", "rack.session",
]

# Pola cookie yang lemah
WEAK_COOKIE_PATTERNS = [
    r"^[a-f0-9]{8}$",             # MD5 pendek
    r"^\d+$",                     # Hanya angka (sequential ID)
    r"^[a-zA-Z0-9]{1,8}$",        # Terlalu pendek
    r"^(admin|test|user|guest)",   # Default value
]

# Default credential pairs
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
]

# Indikator halaman login
LOGIN_INDICATORS = [
    "password", "passwd", "pwd",
    "login", "signin", "log in",
    "username", "email", "user_name",
]


def _is_session_cookie(name: str) -> bool:
    n = name.lower()
    return any(p in n for p in SESSION_COOKIE_PATTERNS)


def _is_weak_cookie_value(value: str) -> bool:
    for pattern in WEAK_COOKIE_PATTERNS:
        if re.match(pattern, value, re.IGNORECASE):
            return True
    # Cek apakah base64-encoded JSON tanpa enkripsi
    try:
        decoded = base64.b64decode(value + "==", validate=False).decode("utf-8", errors="ignore")
        if any(k in decoded for k in ['"user', '"id"', '"role"', '"admin"']):
            return True
    except Exception:
        pass
    return False


def _parse_set_cookie(header: str) -> dict:
    """Parse header Set-Cookie menjadi dict atribut."""
    parts = [p.strip() for p in header.split(";")]
    result = {}
    if parts:
        kv = parts[0].split("=", 1)
        result["name"] = kv[0]
        result["value"] = kv[1] if len(kv) > 1 else ""
    for attr in parts[1:]:
        a = attr.lower()
        result[a.split("=")[0].strip()] = True
    return result


async def _check_cookies(
    http: AsyncHTTPClient,
    url: str,
) -> List[Finding]:
    """Periksa kelemahan cookie pada URL."""
    findings = []
    try:
        resp = await http.get(url)
        if resp.error:
            return []

        # aiohttp menggabungkan Set-Cookie, kita analisis dari header
        cookies_raw = []
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                cookies_raw.append(v)

        for raw in cookies_raw:
            cookie = _parse_set_cookie(raw)
            name  = cookie.get("name", "")
            value = cookie.get("value", "")

            if not _is_session_cookie(name):
                continue

            issues = []

            # Cek flag keamanan
            if "secure" not in cookie:
                issues.append("flag Secure tidak ada (cookie dikirim via HTTP)")
            if "httponly" not in cookie:
                issues.append("flag HttpOnly tidak ada (rentan XSS cookie theft)")
            if "samesite" not in cookie:
                issues.append("flag SameSite tidak ada (rentan CSRF)")

            # Cek nilai cookie
            if _is_weak_cookie_value(value):
                issues.append(f"nilai cookie lemah atau dapat ditebak: '{value[:40]}'")

            if issues:
                findings.append(Finding.from_cvss(
                    cvss_score=6.5,
                    title=f"Konfigurasi Cookie Tidak Aman ({name})",
                    vuln_type=MODULE_NAME,
                    url=url,
                    description=(
                        f"Cookie session '{name}' memiliki konfigurasi yang tidak aman: "
                        + "; ".join(issues)
                    ),
                    evidence=f"Set-Cookie: {raw[:200]}",
                    remediation=(
                        "Set flag Secure, HttpOnly, dan SameSite=Strict/Lax pada semua session cookie. "
                        "Pastikan nilai session ID memiliki entropi yang cukup (min 128-bit)."
                    ),
                    references="https://owasp.org/www-community/controls/SecureCookieAttribute",
                    module=MODULE_NAME,
                    confidence="HIGH",
                ))

    except Exception as exc:
        logger.debug("Cookie check error pada %s: %s", url, exc)

    return findings


def _find_login_form(page: "CrawledURL") -> dict:
    """Temukan form login dari halaman yang di-crawl."""
    for form in page.forms:
        inputs_lower = [i.lower() for i in form.get("inputs", [])]
        has_password = any("pass" in i or "pwd" in i for i in inputs_lower)
        has_user     = any(any(k in i for k in ["user", "email", "login", "name"]) for i in inputs_lower)
        if has_password and has_user:
            return form
    return {}


async def _test_default_creds(
    http: AsyncHTTPClient,
    form: dict,
    page_url: str,
) -> List[Finding]:
    """Coba default credentials pada form login."""
    findings = []
    action = form.get("action", page_url)
    inputs = [i.lower() for i in form.get("inputs", [])]

    user_field = next((i for i in inputs if any(k in i for k in ["user", "email", "login"])), "username")
    pass_field = next((i for i in inputs if "pass" in i or "pwd" in i), "password")

    # Ambil baseline (halaman login)
    try:
        base = await http.get(action if form.get("method", "GET").upper() == "GET" else page_url)
        base_len = len(base.text) if not base.error else 0
    except Exception:
        base_len = 0

    success_indicators = ["dashboard", "welcome", "logout", "sign out", "profile", "my account"]
    fail_indicators = ["invalid", "incorrect", "wrong", "failed", "error", "unauthorized"]

    for username, password in DEFAULT_CREDS[:5]:  # Batasi 5 pasang untuk menghindari lockout
        try:
            method = form.get("method", "POST").upper()
            data = {user_field: username, pass_field: password}

            if method == "POST":
                resp = await http.post(action, data=data)
            else:
                resp = await http.get(action, params=data)

            if resp.error:
                continue

            body_lower = resp.text.lower()

            # Indikator sukses
            has_success = any(ind in body_lower for ind in success_indicators)
            has_fail    = any(ind in body_lower for ind in fail_indicators)

            if has_success and not has_fail:
                findings.append(Finding.from_cvss(
                    cvss_score=9.8,
                    title="Default Credentials Diterima",
                    vuln_type=MODULE_NAME,
                    url=action,
                    method=method,
                    description=(
                        f"Sistem menerima default credentials: "
                        f"username='{username}', password='{password}'. "
                        "Ini memungkinkan akses tidak sah ke sistem."
                    ),
                    evidence=f"Login dengan {username}/{password} tampak berhasil.",
                    payload=f"{username}:{password}",
                    remediation=(
                        "Ubah semua default credentials segera. "
                        "Terapkan kebijakan password yang kuat. "
                        "Aktifkan multi-factor authentication (MFA)."
                    ),
                    references="https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                    module=MODULE_NAME,
                    confidence="MEDIUM",
                ))
                break

        except Exception as exc:
            logger.debug("Default cred test error: %s", exc)

    return findings


async def _check_account_lockout(
    http: AsyncHTTPClient,
    form: dict,
    page_url: str,
) -> List[Finding]:
    """Periksa apakah ada mekanisme account lockout."""
    action = form.get("action", page_url)
    inputs = [i.lower() for i in form.get("inputs", [])]
    user_field = next((i for i in inputs if any(k in i for k in ["user", "email", "login"])), "username")
    pass_field = next((i for i in inputs if "pass" in i or "pwd" in i), "password")

    responses = []
    for i in range(6):  # 6 percobaan
        try:
            resp = await http.post(action, data={
                user_field: "test_lockout_check",
                pass_field: f"wrong_password_{i}",
            })
            if resp.error:
                break
            responses.append(resp.status)
            if resp.status in (429, 403):  # Rate limited
                return []  # Ada proteksi
        except Exception:
            break

    if len(responses) >= 5 and all(s == responses[0] for s in responses):
        # Tidak ada perubahan status → tidak ada lockout
        return [Finding.from_cvss(
            cvss_score=7.5,
            title="Tidak Ada Mekanisme Account Lockout",
            vuln_type=MODULE_NAME,
            url=action,
            method="POST",
            description=(
                "Form login tidak menerapkan account lockout atau rate limiting. "
                "Ini memungkinkan serangan brute force terhadap akun pengguna."
            ),
            evidence=f"6 percobaan berturut-turut, semua mendapat status {responses[0]}.",
            remediation=(
                "Implementasikan account lockout (misalnya: 5 percobaan gagal = lock 15 menit). "
                "Tambahkan CAPTCHA setelah beberapa percobaan gagal. "
                "Terapkan rate limiting pada endpoint autentikasi."
            ),
            references="https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
            module=MODULE_NAME,
            confidence="HIGH",
        )]

    return []


async def scan(
    config: ScanConfig,
    http: AsyncHTTPClient,
    crawled: List[CrawledURL],
) -> List[Finding]:
    """Entry point modul broken authentication."""
    findings: List[Finding] = []
    tasks = []

    for page in crawled:
        tasks.append(_check_cookies(http, page.url))

        login_form = _find_login_form(page)
        if login_form:
            tasks.append(_test_default_creds(http, login_form, page.url))
            tasks.append(_check_account_lockout(http, login_form, page.url))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    return findings
