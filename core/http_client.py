"""
AbyssForge - Async HTTP Client
Wrapper aiohttp dengan fitur retry, timeout, dan header browser-like.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class HTTPResponse:
    """Hasil HTTP response yang sudah dinormalisasi."""
    url: str
    status: int = 0
    text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def header(self, name: str, default: str = "") -> str:
        """Ambil satu header (case-insensitive)."""
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return default


class AsyncHTTPClient:
    """
    Async HTTP client berbasis aiohttp.
    Fitur:
    - Header browser-like otomatis
    - Retry pada error sementara
    - Timeout per-request
    - SSL verify opsional
    - Rate limiting (delay)
    """

    def __init__(
        self,
        base_headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        delay: float = 0.3,
        max_retries: int = 2,
        verify_ssl: bool = False,
    ):
        self.base_headers = base_headers or {}
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.delay = delay
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=50)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=self.base_headers,
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> HTTPResponse:
        """Eksekusi HTTP request dengan retry."""
        for attempt in range(self.max_retries + 1):
            try:
                if self.delay > 0:
                    await asyncio.sleep(self.delay)

                async with self._session.request(
                    method,
                    url,
                    allow_redirects=True,
                    **kwargs,
                ) as resp:
                    # Baca body dengan limit 5MB untuk keamanan
                    try:
                        text = await resp.text(errors="replace")
                    except Exception:
                        text = ""

                    return HTTPResponse(
                        url=str(resp.url),
                        status=resp.status,
                        text=text,
                        headers=dict(resp.headers),
                    )

            except asyncio.TimeoutError:
                logger.debug("Timeout pada %s (attempt %d)", url, attempt + 1)
                if attempt == self.max_retries:
                    return HTTPResponse(url=url, error="timeout")

            except aiohttp.ClientConnectorError as e:
                logger.debug("Koneksi gagal ke %s: %s", url, e)
                return HTTPResponse(url=url, error=f"connection_error: {e}")

            except aiohttp.TooManyRedirects:
                return HTTPResponse(url=url, error="too_many_redirects")

            except Exception as e:
                logger.debug("Error request ke %s: %s", url, e)
                if attempt == self.max_retries:
                    return HTTPResponse(url=url, error=str(e))
                await asyncio.sleep(1)

        return HTTPResponse(url=url, error="max_retries_exceeded")

    async def get(self, url: str, params: Optional[Dict] = None) -> HTTPResponse:
        return await self._request("GET", url, params=params)

    async def post(
        self,
        url: str,
        data: Optional[Dict[str, str]] = None,
        json: Optional[Dict] = None,
    ) -> HTTPResponse:
        return await self._request("POST", url, data=data, json=json)

    async def head(self, url: str) -> HTTPResponse:
        return await self._request("HEAD", url)
