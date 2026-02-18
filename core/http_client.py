"""
AbyssForge - Async HTTP Client
Wrapper async di atas aiohttp dengan retry, rate-limiting, dan logging built-in.
Tidak boleh import modules, database, dashboard, atau reporting.
"""

import asyncio
import logging
import time
from typing import Optional, Dict, Tuple, Any
from urllib.parse import urlparse

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from core.config import ScanConfig

logger = logging.getLogger(__name__)

DEFAULT_UA = (
    "Mozilla/5.0 (compatible; AbyssForge/1.0; +https://github.com/faza-kamal/AbyssForge)"
)


class HTTPResponse:
    """Wrapper response yang konsisten, independen dari library HTTP yang dipakai."""

    def __init__(
        self,
        status: int,
        headers: Dict[str, str],
        text: str,
        url: str,
        elapsed: float,
        error: Optional[str] = None,
    ):
        self.status = status
        self.headers = headers
        self.text = text
        self.url = url
        self.elapsed = elapsed          # detik
        self.error = error

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return default

    def contains(self, pattern: str) -> bool:
        """Periksa apakah body mengandung string tertentu."""
        return pattern.lower() in self.text.lower()

    def __repr__(self) -> str:
        return f"<HTTPResponse {self.status} {self.url} [{self.elapsed:.2f}s]>"


class AsyncHTTPClient:
    """
    Async HTTP client berbasis aiohttp.
    Mendukung session reuse, rate limiting, retry, dan custom headers.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._session: Optional[Any] = None
        self._semaphore = asyncio.Semaphore(config.max_threads)
        self._request_count = 0
        self._last_request_time: float = 0.0

        self.base_headers = {
            "User-Agent": config.user_agent or DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if config.cookie:
            self.base_headers["Cookie"] = config.cookie
        self.base_headers.update(config.extra_headers)

    async def __aenter__(self) -> "AsyncHTTPClient":
        await self._init_session()
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()

    async def _init_session(self) -> None:
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError(
                "aiohttp tidak terinstall. Jalankan: pip install aiohttp"
            )
        connector = aiohttp.TCPConnector(
            ssl=self.config.verify_ssl,
            limit=self.config.max_threads,
            limit_per_host=5,
        )
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        proxy = self.config.proxy or None

        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.base_headers,
            trust_env=False,
        )
        self._proxy = proxy

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _rate_limit(self) -> None:
        """Terapkan delay antar request."""
        if self.config.delay > 0:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self.config.delay:
                await asyncio.sleep(self.config.delay - elapsed)
        self._last_request_time = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        retries: int = 2,
    ) -> HTTPResponse:
        """Kirim HTTP request dengan retry otomatis."""
        if self._session is None:
            await self._init_session()

        merged_headers = {**self.base_headers, **(headers or {})}
        start = time.monotonic()

        async with self._semaphore:
            await self._rate_limit()
            last_error = None

            for attempt in range(retries + 1):
                try:
                    async with self._session.request(
                        method,
                        url,
                        params=params,
                        data=data,
                        json=json,
                        headers=merged_headers,
                        allow_redirects=self.config.follow_redirects,
                        proxy=self._proxy if hasattr(self, "_proxy") else None,
                    ) as resp:
                        elapsed = time.monotonic() - start
                        body = await resp.text(errors="replace")
                        resp_headers = dict(resp.headers)
                        self._request_count += 1

                        logger.debug(
                            "[%s] %s %s → %d (%.2fs)",
                            attempt, method, url, resp.status, elapsed,
                        )

                        return HTTPResponse(
                            status=resp.status,
                            headers=resp_headers,
                            text=body,
                            url=str(resp.url),
                            elapsed=elapsed,
                        )

                except asyncio.TimeoutError:
                    last_error = "Timeout"
                    logger.debug("Timeout pada %s (attempt %d)", url, attempt)
                except Exception as exc:
                    last_error = str(exc)
                    logger.debug("Error %s pada %s (attempt %d)", exc, url, attempt)

                if attempt < retries:
                    await asyncio.sleep(1.0 * (attempt + 1))

            elapsed = time.monotonic() - start
            return HTTPResponse(
                status=0,
                headers={},
                text="",
                url=url,
                elapsed=elapsed,
                error=last_error or "Unknown error",
            )

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("HEAD", url, **kwargs)

    @property
    def total_requests(self) -> int:
        return self._request_count
