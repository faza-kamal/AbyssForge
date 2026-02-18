"""
AbyssForge - URL & Domain Validator
Utilitas validasi dan sanitasi URL.
"""

import re
from urllib.parse import urlparse, urljoin, parse_qs
from typing import Optional, Tuple


# RFC-3986 sederhana
_URL_RE = re.compile(
    r'^https?://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
    r'localhost|'
    r'\d{1,3}(?:\.\d{1,3}){3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$',
    re.IGNORECASE,
)


def is_valid_url(url: str) -> bool:
    """Kembalikan True jika url adalah URL HTTP/HTTPS yang valid."""
    return bool(_URL_RE.match(url.strip()))


def normalize_url(url: str) -> str:
    """
    Pastikan URL memiliki skema (default https://),
    dan hapus trailing slash berlebih.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    # Pastikan path tidak kosong
    path = parsed.path or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def extract_domain(url: str) -> str:
    """Ekstrak netloc dari URL."""
    return urlparse(url).netloc


def inject_param(url: str, param: str, value: str) -> str:
    """
    Ganti nilai parameter di URL, atau tambahkan jika belum ada.
    Berguna untuk menyisipkan payload ke parameter GET.
    """
    from urllib.parse import urlencode, urlunparse, parse_qs

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, ""
    ))


def get_params(url: str) -> dict:
    """Kembalikan dict query params dari URL."""
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def same_domain(url1: str, url2: str) -> bool:
    """Periksa apakah dua URL berada pada domain yang sama."""
    return urlparse(url1).netloc == urlparse(url2).netloc
