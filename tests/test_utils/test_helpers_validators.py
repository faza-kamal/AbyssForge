"""
Tests for AbyssForge utility functions.
"""

import pytest
from abyssforge.utils.validators import (
    validate_url,
    validate_proxy,
    validate_threads,
    validate_timeout,
    is_valid_ip,
    is_valid_domain,
    sanitize_filename,
)
from abyssforge.utils.helpers import (
    load_payloads,
    get_url_params,
    inject_param,
    format_bytes,
    is_same_domain,
    severity_score,
)
from abyssforge.core.exceptions import ValidationError


class TestValidators:
    """Test URL and input validators."""

    def test_validate_url_valid(self):
        assert validate_url("https://example.com") == "https://example.com"

    def test_validate_url_adds_scheme(self):
        result = validate_url("example.com")
        assert result.startswith("https://")

    def test_validate_url_empty_raises(self):
        with pytest.raises(ValidationError):
            validate_url("")

    def test_validate_url_invalid_raises(self):
        with pytest.raises(ValidationError):
            validate_url("not_a_url_without_domain")

    def test_is_valid_ip(self):
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("255.255.255.255") is True
        assert is_valid_ip("256.1.1.1") is False
        assert is_valid_ip("not_an_ip") is False

    def test_is_valid_domain(self):
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.co.uk") is True
        assert is_valid_domain("invalid") is False

    def test_sanitize_filename(self):
        result = sanitize_filename("file<>:name.txt")
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result

    def test_validate_threads_valid(self):
        assert validate_threads(10) is True
        assert validate_threads(1) is True
        assert validate_threads(100) is True

    def test_validate_threads_invalid(self):
        with pytest.raises(ValidationError):
            validate_threads(0)
        with pytest.raises(ValidationError):
            validate_threads(101)

    def test_validate_timeout_valid(self):
        assert validate_timeout(30) is True

    def test_validate_timeout_invalid(self):
        with pytest.raises(ValidationError):
            validate_timeout(0)
        with pytest.raises(ValidationError):
            validate_timeout(301)


class TestHelpers:
    """Test helper utility functions."""

    def test_get_url_params(self):
        url = "https://example.com?id=1&name=test"
        params = get_url_params(url)
        assert "id" in params
        assert "name" in params
        assert params["id"] == ["1"]

    def test_get_url_params_no_params(self):
        params = get_url_params("https://example.com")
        assert params == {}

    def test_inject_param(self):
        url = "https://example.com?id=1"
        result = inject_param(url, "id", "' OR 1=1--")
        assert "id=" in result
        assert "OR+1%3D1" in result or "OR 1=1" in result or "%27" in result

    def test_format_bytes(self):
        assert "B" in format_bytes(500)
        assert "KB" in format_bytes(1500)
        assert "MB" in format_bytes(1500000)

    def test_is_same_domain(self):
        assert is_same_domain("https://example.com/page1", "https://example.com/page2") is True
        assert is_same_domain("https://example.com", "https://other.com") is False

    def test_severity_score(self):
        assert severity_score("critical") == 4
        assert severity_score("high") == 3
        assert severity_score("medium") == 2
        assert severity_score("low") == 1
        assert severity_score("info") == 0

    def test_load_payloads_nonexistent_file(self):
        payloads = load_payloads("/nonexistent/path/file.txt")
        assert payloads == []
