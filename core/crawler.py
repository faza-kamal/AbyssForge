"""
AbyssForge - Web Crawler v2 (Robust)
- Body disimpan di CrawledURL (tidak perlu re-fetch di modul)
- Verbose debug agar jelas kenapa bisa 0 URL
- Link extraction lebih akurat
- Form parsing lebih baik
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse

from core.config import ScanConfig
from core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)

_HREF_RE = re.compile(
    r'(?:href|src|action)\s*=\s*["\']([^"\'#][^"\']*)["\']',
    re.IGNORECASE,
)
_JS_URL_RE = re.compile(
    r'(?:fetch|axios\.get|\.open|location\.href\s*=)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_FORM_RE  = re.compile(r'<form([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_ATTR_RE  = re.compile(r'(\w[\w-]*)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_NAME_RE  = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

_SKIP_EXTS = {
    ".jpg",".jpeg",".png",".gif",".svg",".webp",".ico",
    ".css",".js",".woff",".woff2",".ttf",".eot",
    ".pdf",".zip",".rar",".tar",".gz",".mp4",".mp3",
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",
}


@dataclass
class CrawledURL:
    url: str
    status: int
    params: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    depth: int = 0
    content_type: str = ""
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def has_params(self): return bool(self.params)
    @property
    def has_forms(self):  return bool(self.forms)


class Crawler:
    def __init__(self, config: ScanConfig, http: AsyncHTTPClient):
        self.config = config
        self.http   = http
        self._visited: Set[str] = set()
        parsed = urlparse(config.target_url)
        self._base_domain = parsed.netloc

    def _normalize(self, url: str, base: str) -> Optional[str]:
        try:
            url = url.strip()
            if not url or url.startswith(("#","javascript:","mailto:","tel:","data:","void")):
                return None
            resolved = urljoin(base, url)
            parsed   = urlparse(resolved)
            if parsed.scheme not in ("http","https"):
                return None
            if parsed.netloc != self._base_domain:
                return None
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in _SKIP_EXTS):
                return None
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, parsed.query, ""))
        except Exception:
            return None

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        links: Set[str] = set()
        for raw in _HREF_RE.findall(html):
            u = self._normalize(raw, base_url)
            if u: links.add(u)
        for raw in _JS_URL_RE.findall(html):
            u = self._normalize(raw, base_url)
            if u: links.add(u)
        return links

    def _extract_params(self, url: str) -> List[str]:
        return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        forms = []
        for attrs_str, body in _FORM_RE.findall(html):
            attrs      = dict(_ATTR_RE.findall(attrs_str))
            raw_action = attrs.get("action", "") or base_url
            action     = self._normalize(raw_action, base_url) or base_url
            method     = attrs.get("method", "GET").upper()
            inputs     = _NAME_RE.findall(body)
            if inputs:
                forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    async def _crawl_one(self, url: str, depth: int) -> Optional[Tuple]:
        if url in self._visited:
            return None
        self._visited.add(url)

        resp = await self.http.get(url)
        if resp.error:
            logger.debug("[crawl] FAIL %s → %s", url, resp.error)
            return None
        if resp.status >= 400:
            logger.debug("[crawl] HTTP %d skipped: %s", resp.status, url)
            return None

        self._visited.add(resp.url)  # URL setelah redirect

        params = self._extract_params(resp.url)
        forms  = self._extract_forms(resp.text, resp.url)
        links  = self._extract_links(resp.text, resp.url)

        logger.debug("[crawl] ✓ %s | status=%d params=%s forms=%d links=%d",
                     resp.url, resp.status, params, len(forms), len(links))

        crawled = CrawledURL(
            url=resp.url, status=resp.status,
            params=params, forms=forms, depth=depth,
            content_type=resp.header("Content-Type",""),
            body=resp.text, headers=resp.headers,
        )
        return crawled, links

    async def crawl(self) -> List[CrawledURL]:
        target    = self.config.target_url
        max_depth = self.config.crawl_depth
        results: List[CrawledURL] = []
        queue: List[tuple] = [(target, 0)]

        while queue:
            current_depth = queue[0][1]
            batch   = [i for i in queue if i[1] == current_depth]
            queue   = [i for i in queue if i[1] != current_depth]
            sem     = asyncio.Semaphore(5)

            async def _do(url, depth):
                async with sem:
                    return await self._crawl_one(url, depth)

            task_results = await asyncio.gather(
                *[_do(u, d) for u, d in batch], return_exceptions=True
            )

            for result in task_results:
                if isinstance(result, Exception) or result is None:
                    continue
                crawled_url, links = result
                results.append(crawled_url)
                if current_depth < max_depth:
                    for link in links:
                        if link not in self._visited:
                            queue.append((link, current_depth + 1))

        logger.info("[crawl] selesai: %d halaman dari %s", len(results), target)
        return results
