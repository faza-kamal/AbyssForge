"""
AbyssForge HTTP Request Handler
Handles all HTTP requests with retry logic, rate limiting, and proxy support.
"""

import asyncio
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from abyssforge.core.exceptions import RequestError, TimeoutError
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.request")


class RateLimiter:
    """Token bucket rate limiter for controlling request frequency."""

    def __init__(self, rate: float) -> None:
        """
        Initialize rate limiter.

        Args:
            rate: Maximum requests per second
        """
        self.rate = rate
        self.tokens = rate
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to make a request."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class RequestHandler:
    """
    Handles HTTP requests with session management, retry logic, and proxy support.
    """

    DEFAULT_HEADERS = {
        "User-Agent": "AbyssForge/1.0.0 Security Scanner",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        verify_ssl: bool = False,
        rate_limit: float = 10.0,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.rate_limiter = RateLimiter(rate_limit)

        # Build headers
        self.headers = {**self.DEFAULT_HEADERS}
        if headers:
            self.headers.update(headers)

        # Setup requests session
        self.session = self._create_session(cookies)

    def _create_session(self, cookies: Optional[Dict[str, str]] = None) -> requests.Session:
        """Create a configured requests session."""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update(self.headers)
        session.verify = self.verify_ssl

        if cookies:
            session.cookies.update(cookies)

        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}

        return session

    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        """
        Make a synchronous GET request.

        Args:
            url: Target URL
            params: Optional query parameters
            extra_headers: Additional headers for this request

        Returns:
            Response object

        Raises:
            RequestError: If request fails
        """
        headers = {**self.headers}
        if extra_headers:
            headers.update(extra_headers)

        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
            )
            return response
        except requests.exceptions.Timeout:
            raise TimeoutError(f"Request timed out: {url}")
        except requests.exceptions.RequestException as e:
            raise RequestError(f"GET request failed: {e}")

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        """Make a synchronous POST request."""
        headers = {**self.headers}
        if extra_headers:
            headers.update(extra_headers)

        try:
            response = self.session.post(
                url,
                data=data,
                json=json_data,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
            )
            return response
        except requests.exceptions.Timeout:
            raise TimeoutError(f"Request timed out: {url}")
        except requests.exceptions.RequestException as e:
            raise RequestError(f"POST request failed: {e}")

    async def async_get(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, float, Dict[str, str]]:
        """
        Make an asynchronous GET request.

        Args:
            session: aiohttp ClientSession
            url: Target URL
            params: Optional query parameters
            extra_headers: Additional headers

        Returns:
            Tuple of (status_code, response_text, response_time_ms, response_headers)
        """
        await self.rate_limiter.acquire()

        headers = {**self.headers}
        if extra_headers:
            headers.update(extra_headers)

        start_time = time.monotonic()

        for attempt in range(self.max_retries):
            try:
                async with session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=self.verify_ssl,
                    allow_redirects=True,
                ) as response:
                    text = await response.text(errors="replace")
                    elapsed = (time.monotonic() - start_time) * 1000
                    return (
                        response.status,
                        text,
                        elapsed,
                        dict(response.headers),
                    )
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    raise TimeoutError(f"Async request timed out: {url}")
                await asyncio.sleep(self.retry_delay * (2**attempt))
            except aiohttp.ClientError as e:
                if attempt == self.max_retries - 1:
                    raise RequestError(f"Async GET failed: {e}")
                await asyncio.sleep(self.retry_delay * (2**attempt))

        raise RequestError(f"All retry attempts failed for: {url}")

    async def async_post(
        self,
        session: aiohttp.ClientSession,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, float, Dict[str, str]]:
        """Make an asynchronous POST request."""
        await self.rate_limiter.acquire()

        headers = {**self.headers}
        if extra_headers:
            headers.update(extra_headers)

        start_time = time.monotonic()

        for attempt in range(self.max_retries):
            try:
                async with session.post(
                    url,
                    data=data,
                    json=json_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=self.verify_ssl,
                ) as response:
                    text = await response.text(errors="replace")
                    elapsed = (time.monotonic() - start_time) * 1000
                    return (
                        response.status,
                        text,
                        elapsed,
                        dict(response.headers),
                    )
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    raise TimeoutError(f"Async request timed out: {url}")
                await asyncio.sleep(self.retry_delay * (2**attempt))
            except aiohttp.ClientError as e:
                if attempt == self.max_retries - 1:
                    raise RequestError(f"Async POST failed: {e}")
                await asyncio.sleep(self.retry_delay * (2**attempt))

        raise RequestError(f"All retry attempts failed for: {url}")

    def create_async_session(self) -> aiohttp.ClientSession:
        """Create an aiohttp session with proper configuration."""
        connector = aiohttp.TCPConnector(
            ssl=self.verify_ssl,
            limit=100,
        )

        proxy = self.proxy if self.proxy else None

        return aiohttp.ClientSession(
            headers=self.headers,
            connector=connector,
            trust_env=True,
        )

    def measure_response_time(self, url: str) -> float:
        """
        Measure response time for a URL.

        Args:
            url: Target URL

        Returns:
            Response time in milliseconds
        """
        start = time.monotonic()
        try:
            self.get(url)
        except Exception:
            pass
        return (time.monotonic() - start) * 1000

    def close(self) -> None:
        """Close the requests session."""
        self.session.close()
