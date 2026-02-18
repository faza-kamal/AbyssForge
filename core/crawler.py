"""
AbyssForge - Web Crawler
Async crawler untuk menemukan URL dari sitemap, link HTML, dan form.
Tidak boleh import modules, database, dashboard, atau reporting.
"""

import asyncio
import logging
import re
from typing import Set, List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from core.config import ScanConfig
from core.http_client import AsyncHTTPClient, HTTPResponse

logger = logging.getLogger(__name__)

# Ekstensi yang di-skip (aset statis)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".zip", ".tar", ".gz",
    ".pdf", ".doc", ".xls", ".ppt",
}

# Regex untuk ekstrak URL dari HTML
HREF_RE = re.compile(r'href=["\']([^"\'#>]+)["\']', re.IGNORECASE)
SRC_RE  = re.compile(r'src=["\']([^"\'#>]+)["\']', re.IGNORECASE)
ACTION_RE = re.compile(r'action=["\']([^"\'#>]+)["\']', re.IGNORECASE)

# Form input regex
INPUT_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE,
)
TEXTAREA_RE = re.compile(
    r'<textarea[^>]+name=["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE,
)


class CrawledURL:
    """Merepresentasikan satu URL yang berhasil di-crawl beserta metadata-nya."""

    def __init__(
        self,
        url: str,
        status: int,
        content_type: str,
        depth: int,
        forms: List[Dict],
        params: Dict[str, str],
        response: Optional[HTTPResponse] = None,
    ):
        self.url = url
        self.status = status
        self.content_type = content_type
        self.depth = depth
        self.forms = forms          # [{"action": url, "method": "post", "inputs": [...]}]
        self.params = params        # query parameter dari URL
        self.response = response    # referensi response asli (opsional)

    def __repr__(self) -> str:
        return f"<CrawledURL [{self.status}] {self.url} depth={self.depth}>"


class WebCrawler:
    """
    Async web crawler.
    Mengunjungi URL secara BFS hingga kedalaman tertentu,
    mengekstrak link, form, dan parameter.
    """

    def __init__(self, config: ScanConfig, http: AsyncHTTPClient):
        self.config = config
        self.http = http
        self.base_domain = urlparse(config.target_url).netloc
        self.visited: Set[str] = set()
        self.results: List[CrawledURL] = []
        self._queue: asyncio.Queue = asyncio.Queue()

    def _normalize_url(self, url: str, base: str) -> Optional[str]:
        """Normalisasi URL relatif ke absolut, filter non-scope."""
        try:
            full = urljoin(base, url.strip())
            parsed = urlparse(full)

            # Hanya HTTP/HTTPS
            if parsed.scheme not in ("http", "https"):
                return None

            # Hanya domain yang sama (scope)
            if parsed.netloc != self.base_domain:
                return None

            # Lewati ekstensi statis
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in SKIP_EXTENSIONS):
                return None

            # Hapus fragment, normalisasi
            clean = urlunparse((
                parsed.scheme, parsed.netloc,
                parsed.path, parsed.params, parsed.query, ""
            ))
            return clean
        except Exception:
            return None

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        """Ekstrak semua link dari HTML."""
        links: Set[str] = set()
        for pattern in (HREF_RE, SRC_RE, ACTION_RE):
            for match in pattern.finditer(html):
                url = self._normalize_url(match.group(1), base_url)
                if url:
                    links.add(url)
        return links

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Ekstrak semua form beserta action, method, dan input fields."""
        forms = []
        form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        form_headers = re.findall(r'<form([^>]*)>', html, re.IGNORECASE)

        for i, (header, body) in enumerate(zip(form_headers, form_blocks)):
            action_m = re.search(r'action=["\']([^"\']+)["\']', header, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']+)["\']', header, re.IGNORECASE)

            action = self._normalize_url(action_m.group(1), base_url) if action_m else base_url
            method = method_m.group(1).upper() if method_m else "GET"

            inputs = INPUT_RE.findall(body) + TEXTAREA_RE.findall(body)
            forms.append({
                "action": action or base_url,
                "method": method,
                "inputs": inputs,
            })

        return forms

    def _extract_params(self, url: str) -> Dict[str, str]:
        """Ekstrak query parameter dari URL."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return {k: v[0] for k, v in qs.items()}

    async def _fetch_sitemap(self) -> Set[str]:
        """Coba ambil sitemap.xml untuk mendapatkan daftar URL."""
        urls: Set[str] = set()
        sitemap_urls = [
            f"{self.config.target_url.rstrip('/')}/sitemap.xml",
            f"{self.config.target_url.rstrip('/')}/sitemap_index.xml",
        ]
        for sm_url in sitemap_urls:
            resp = await self.http.get(sm_url)
            if resp.ok and "<url>" in resp.text.lower():
                loc_matches = re.findall(r'<loc>(.*?)</loc>', resp.text, re.IGNORECASE)
                for loc in loc_matches:
                    norm = self._normalize_url(loc, sm_url)
                    if norm:
                        urls.add(norm)
                logger.info("Sitemap ditemukan, %d URL terindeks.", len(urls))
        return urls

    async def _process_url(self, url: str, depth: int) -> Optional[CrawledURL]:
        """Fetch satu URL dan ekstrak data."""
        if url in self.visited:
            return None
        self.visited.add(url)

        resp = await self.http.get(url)
        if not resp.ok:
            return None

        content_type = resp.header("Content-Type", "")
        forms = []
        links: Set[str] = set()

        if "text/html" in content_type:
            links = self._extract_links(resp.text, url)
            forms = self._extract_forms(resp.text, url)

        params = self._extract_params(url)

        crawled = CrawledURL(
            url=url,
            status=resp.status,
            content_type=content_type,
            depth=depth,
            forms=forms,
            params=params,
            response=resp,
        )

        # Tambah link baru ke queue
        if depth < self.config.crawl_depth:
            for link in links:
                if link not in self.visited:
                    await self._queue.put((link, depth + 1))

        return crawled

    async def crawl(self) -> List[CrawledURL]:
        """
        Mulai crawl dari target URL.
        Kembalikan list CrawledURL yang berhasil di-crawl.
        """
        logger.info("Memulai crawl: %s (depth=%d)", self.config.target_url, self.config.crawl_depth)

        # Ambil sitemap lebih dulu
        sitemap_urls = await self._fetch_sitemap()
        await self._queue.put((self.config.target_url, 0))
        for su in sitemap_urls:
            await self._queue.put((su, 1))

        workers_done = False
        tasks: List[asyncio.Task] = []

        while not self._queue.empty() or tasks:
            # Batasi jumlah URL
            if len(self.visited) >= self.config.max_urls_per_domain:
                logger.info("Batas URL tercapai (%d).", self.config.max_urls_per_domain)
                break

            # Jalankan workers sampai batas thread
            while not self._queue.empty() and len(tasks) < self.config.max_threads:
                url, depth = await self._queue.get()
                if url not in self.visited:
                    task = asyncio.create_task(self._process_url(url, depth))
                    tasks.append(task)

            if not tasks:
                break

            # Tunggu setidaknya satu selesai
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            tasks = list(pending)

            for task in done:
                try:
                    result = task.result()
                    if result:
                        self.results.append(result)
                        logger.debug("Crawled: %s", result.url)
                except Exception as exc:
                    logger.debug("Crawl error: %s", exc)

        # Tunggu sisa task
        if tasks:
            done = await asyncio.gather(*tasks, return_exceptions=True)
            for r in done:
                if isinstance(r, CrawledURL) and r:
                    self.results.append(r)

        logger.info(
            "Crawl selesai: %d URL ditemukan dari %d dikunjungi.",
            len(self.results), len(self.visited),
        )
        return self.results
