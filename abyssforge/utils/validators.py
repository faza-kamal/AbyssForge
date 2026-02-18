"""
AbyssForge Input Validators
"""

import re
from typing import Optional
from urllib.parse import urlparse

from abyssforge.core.exceptions import ValidationError


def validate_url(url: str) -> str:
    """
    Validate and normalize a URL.

    Args:
        url: URL string to validate

    Returns:
        Normalized URL string

    Raises:
        ValidationError: If URL is invalid
    """
    if not url:
        raise ValidationError("URL cannot be empty")

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValidationError(f"Invalid URL: {url}")
        if parsed.scheme not in ("http", "https"):
            raise ValidationError(f"Unsupported URL scheme: {parsed.scheme}")
    except Exception as e:
        raise ValidationError(f"URL parsing failed: {e}")

    return url


def validate_proxy(proxy: str) -> bool:
    """
    Validate proxy URL format.

    Args:
        proxy: Proxy URL string

    Returns:
        True if valid

    Raises:
        ValidationError: If proxy URL is invalid
    """
    valid_schemes = ("http://", "https://", "socks4://", "socks5://")
    if not any(proxy.startswith(s) for s in valid_schemes):
        raise ValidationError(f"Invalid proxy format. Must start with: {valid_schemes}")
    return True


def validate_threads(threads: int) -> bool:
    """Validate thread count."""
    if not 1 <= threads <= 100:
        raise ValidationError("Thread count must be between 1 and 100")
    return True


def validate_timeout(timeout: int) -> bool:
    """Validate timeout value."""
    if not 1 <= timeout <= 300:
        raise ValidationError("Timeout must be between 1 and 300 seconds")
    return True


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return bool(re.match(pattern, ip))


def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain name."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename by removing invalid characters."""
    return re.sub(r'[<>:"/\\|?*]', "_", filename)


def validate_severity(severity: str) -> bool:
    """Validate severity level."""
    valid = {"critical", "high", "medium", "low", "info"}
    if severity.lower() not in valid:
        raise ValidationError(f"Invalid severity: {severity}. Must be one of: {valid}")
    return True


def validate_output_format(fmt: str) -> bool:
    """Validate report output format."""
    valid = {"json", "html", "markdown", "csv"}
    if fmt.lower() not in valid:
        raise ValidationError(f"Invalid format: {fmt}. Must be one of: {valid}")
    return True
