"""
AbyssForge Test Configuration and Fixtures
"""

import pytest
import responses as resp_lib
from unittest.mock import MagicMock

from abyssforge.core.request import RequestHandler
from abyssforge.core.engine import ScanEngine


@pytest.fixture
def sample_config():
    """Basic configuration for testing."""
    return {
        "scanner": {
            "threads": 2,
            "timeout": 10,
            "max_retries": 1,
            "retry_delay": 0.1,
            "rate_limit": 100.0,
            "verify_ssl": False,
        },
        "modules": {
            "sqli": {"enabled": True, "time_delay": 1},
            "xss": {"enabled": True, "max_payloads": 5},
            "csrf": {"enabled": True},
            "lfi": {"enabled": True},
            "cmd_injection": {"enabled": True},
            "misconfig": {"enabled": True},
            "api_security": {"enabled": True},
        },
        "proxy": {"enabled": False},
        "headers": {"default": {}},
    }


@pytest.fixture
def request_handler():
    """Create a request handler for testing."""
    return RequestHandler(
        timeout=10,
        max_retries=1,
        retry_delay=0.1,
        rate_limit=100.0,
        verify_ssl=False,
    )


@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    response = MagicMock()
    response.status_code = 200
    response.text = "<html><body>Hello World</body></html>"
    response.headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "Apache/2.4",
    }
    return response


@pytest.fixture
def sql_error_response():
    """Mock response with SQL error."""
    response = MagicMock()
    response.status_code = 200
    response.text = "You have an error in your SQL syntax; check the manual"
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def xss_reflected_response():
    """Mock response with XSS reflection."""
    response = MagicMock()
    response.status_code = 200
    response.text = "<html><body><script>alert(1)</script></body></html>"
    response.headers = {"Content-Type": "text/html"}
    return response


@pytest.fixture
def secure_response():
    """Mock response with all security headers set."""
    response = MagicMock()
    response.status_code = 200
    response.text = "<html><body>Secure Page</body></html>"
    response.headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    return response
