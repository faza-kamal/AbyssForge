"""
AbyssForge - Web Crawler (Robust)
Crawl halaman web secara rekursif dengan:
- Header browser-like (bypass WAF dasar)
- Penanganan URL relatif & absolut
- Deteksi form dan input fields
- Ekstraksi query params
- Retry & error handling
- Respect crawl depth
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse

from core.config import ScanConfig
from core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)

# ─── Regex untuk ekstraksi link ───────────────────────────────────────────────

# Cari semua href="" dan src="" (termasuk link JS sederhana)
_HREF_RE = re.compile(
    r'(?:href|src|action)\s*=\s*["\']([^"\'#\s][^"\']*)["\']',
    re.IGNORECASE,
)

# Link di dalam JavaScript (window.location, fetch, axios, dll)
_JS_URL_RE = re.compile(
    r'(?:fetch|axios\.get|window\.location\.href\s*=|\.open)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Ekstraksi form
_FORM_RE = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_NAME_RE = re.compile(
    r'<(?:input|textarea|select)[^>]*name\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Ekstensi yang tidak perlu di-crawl
_SKIP_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".rar", ".tar", ".gz", ".mp4", ".mp3",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}


@dataclass
class CrawledURL:
    """Satu halaman yang berhasil di-crawl."""
    url: str
    status: int
    params: List[str] = field(default_factory=list)      # Query param names
    forms: List[Dict] = field(default_factory=list)       # List of form dicts
    depth: int = 0
    content_type: str = ""

    @property
    def has_params(self) -> bool:
        return bool(self.params)

    @property
    def has_forms(self) -> bool:
        return bool(self.forms)


class Crawler:
    """
    Web crawler async dengan penanganan robust untuk:
    - Situs dengan WAF/Cloudflare (header browser-like)
    - URL relatif dan absolut
    - Form detection
    - Link di dalam JS
    - Redirect
    """

    def __init__(self, config: ScanConfig, http: AsyncHTTPClient):
        self.config = config
        self.http = http
        self._visited: Set[str] = set()
        self._base_domain = urlparse(config.target_url).netloc

    # ─── URL helpers ──────────────────────────────────────────────────────────

    def _normalize(self, url: str, base: str) -> Optional[str]:
        """Normalisasi URL relatif menjadi absolut, filter non-HTTP."""
        try:
            url = url.strip()

            # Lewati URL kosong, fragment, javascript:, mailto:, dll
            if not url or url.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                return None

            # Resolve URL relatif ke absolut
            resolved = urljoin(base, url)

            parsed = urlparse(resolved)

            # Hanya HTTP/HTTPS
            if parsed.scheme not in ("http", "https"):
                return None

            # Hanya domain yang sama (in-scope)
            if parsed.netloc != self._base_domain:
                return None

            # Lewati ekstensi file statis
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in _SKIP_EXTS):
                return None

            # Hapus fragment (#...) dari URL
            clean = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, parsed.query, ""
            ))
            return clean
        except Exception:
            return None

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        """Ekstrak semua link unik dari HTML dan JS inline."""
        links: Set[str] = set()

        for raw in _HREF_RE.findall(html):
            url = self._normalize(raw, base_url)
            if url:
                links.add(url)

        for raw in _JS_URL_RE.findall(html):
            url = self._normalize(raw, base_url)
            if url:
                links.add(url)

        return links

    def _extract_params(self, url: str) -> List[str]:
        """Ekstrak nama-nama query parameter dari URL."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        return list(qs.keys())

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Ekstrak semua form beserta action, method, dan input names."""
        forms = []
        for form_html in _FORM_RE.findall(html):
            action_m = _ACTION_RE.search(form_html)
            method_m = _METHOD_RE.search(form_html)

            raw_action = action_m.group(1) if action_m else base_url
            action = self._normalize(raw_action, base_url) or base_url
            method = (method_m.group(1) if method_m else "GET").upper()

            inputs = _INPUT_NAME_RE.findall(form_html)
            if inputs:
                forms.append({
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                })
        return forms

    # ─── Core crawl ───────────────────────────────────────────────────────────

    async def _crawl_one(self, url: str, depth: int) -> Optional[CrawledURL]:
        """Crawl satu URL, kembalikan CrawledURL atau None jika gagal."""
        if url in self._visited:
            return None
        self._visited.add(url)

        logger.debug("Crawling [depth=%d]: %s", depth, url)

        resp = await self.http.get(url)

        if resp.error:
            logger.debug("Error crawling %s: %s", url, resp.error)
            return None

        # Lewati response non-HTML
        content_type = resp.header("Content-Type", "")
        if resp.status not in range(200, 400):
            # Tetap proses 200-399 (termasuk redirect yang sudah di-follow)
            logger.debug("Status %d untuk %s", resp.status, url)
            if resp.status >= 400:
                return None

        params = self._extract_params(resp.url)  # URL final setelah redirect
        forms = self._extract_forms(resp.text, resp.url)

        crawled = CrawledURL(
            url=resp.url,  # URL setelah redirect
            status=resp.status,
            params=params,
            forms=forms,
            depth=depth,
            content_type=content_type,
        )

        # Tambahkan URL asli sebagai sudah dikunjungi (untuk redirect)
        self._visited.add(resp.url)

        return crawled, self._extract_links(resp.text, resp.url)

    async def crawl(self) -> List[CrawledURL]:
        """
        Mulai crawl dari target URL.
        Return: list CrawledURL yang berhasil dikunjungi.
        """
        target = self.config.target_url
        max_depth = self.config.crawl_depth
        results: List[CrawledURL] = []

        # Queue: (url, depth)
        queue: List[tuple] = [(target, 0)]

        while queue:
            # Ambil batch berdasarkan depth yang sama
            current_depth = queue[0][1]
            batch = []
            remaining = []

            for item in queue:
                if item[1] == current_depth:
                    batch.append(item)
                else:
                    remaining.append(item)

            queue = remaining

            # Crawl batch secara concurrent (max 5 sekaligus)
            semaphore = asyncio.Semaphore(5)

            async def crawl_with_sem(url: str, depth: int):
                async with semaphore:
                    return await self._crawl_one(url, depth)

            tasks = [crawl_with_sem(url, depth) for url, depth in batch]
            task_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in task_results:
                if isinstance(result, Exception) or result is None:
                    continue

                crawled_url, links = result
                results.append(crawled_url)

                # Tambah link ke queue jika belum mencapai max depth
                if current_depth < max_depth:
                    for link in links:
                        if link not in self._visited:
                            queue.append((link, current_depth + 1))

        logger.info(
            "Crawl selesai: %d URL ditemukan dari %s (depth=%d)",
            len(results), target, max_depth,
        )
        return results
