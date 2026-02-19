"""
Tests for core scanner modules.
"""

import pytest
from unittest.mock import MagicMock, patch

from abyssforge.core.parser import ResponseParser
from abyssforge.modules.base import Finding


class TestResponseParser:
    """Test ResponseParser functionality."""

    def test_detect_mysql_error(self):
        parser = ResponseParser(
            "You have an error in your SQL syntax; check the manual",
            200,
            {"Content-Type": "text/html"},
        )
        errors = parser.detect_sql_errors()
        assert len(errors) > 0

    def test_no_sql_errors_in_normal_response(self):
        parser = ResponseParser(
            "<html><body>Hello World</body></html>",
            200,
            {"Content-Type": "text/html"},
        )
        errors = parser.detect_sql_errors()
        assert len(errors) == 0

    def test_detect_wordpress(self):
        parser = ResponseParser(
            '<link rel="stylesheet" href="/wp-content/themes/style.css">',
            200,
            {},
        )
        techs = parser.detect_technologies()
        assert "WordPress" in techs

    def test_detect_django(self):
        parser = ResponseParser(
            '<input type="hidden" name="csrfmiddlewaretoken" value="abc">',
            200,
            {},
        )
        techs = parser.detect_technologies()
        assert "Django" in techs

    def test_extract_forms_basic(self):
        html = """
        <form action="/login" method="POST">
            <input name="username" type="text">
            <input name="password" type="password">
            <input type="submit" value="Login">
        </form>
        """
        parser = ResponseParser(html, 200, {})
        forms = parser.extract_forms()
        assert len(forms) == 1
        assert forms[0]["method"] == "POST"
        assert len(forms[0]["inputs"]) == 2

    def test_security_headers_missing(self):
        parser = ResponseParser("", 200, {"Content-Type": "text/html"})
        headers = parser.check_security_headers()
        assert not headers["Strict-Transport-Security"]["present"]
        assert not headers["Content-Security-Policy"]["present"]

    def test_security_headers_present(self):
        parser = ResponseParser(
            "",
            200,
            {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
            },
        )
        headers = parser.check_security_headers()
        assert headers["Strict-Transport-Security"]["present"]
        assert headers["Content-Security-Policy"]["present"]
        assert headers["X-Frame-Options"]["present"]

    def test_detect_cloudflare_waf(self):
        parser = ResponseParser(
            "",
            200,
            {"cf-ray": "abc123", "Server": "cloudflare"},
        )
        waf = parser.detect_waf()
        assert waf == "Cloudflare"

    def test_no_waf_detected(self):
        parser = ResponseParser("", 200, {"Server": "Apache/2.4"})
        waf = parser.detect_waf()
        assert waf is None


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_to_dict(self):
        finding = Finding(
            vuln_type="SQL Injection",
            url="https://example.com?id=1",
            parameter="id",
            payload="'",
            severity="critical",
            evidence="SQL error detected",
            description="SQL injection found",
            remediation="Use parameterized queries",
            cwe="CWE-89",
        )

        d = finding.to_dict()
        assert d["vuln_type"] == "SQL Injection"
        assert d["severity"] == "critical"
        assert d["cwe"] == "CWE-89"
        assert "timestamp" in d

    def test_finding_default_confidence(self):
        finding = Finding(
            vuln_type="XSS",
            url="https://example.com",
            parameter="q",
            payload="<script>alert(1)</script>",
            severity="high",
            evidence="XSS found",
            description="Cross-site scripting",
            remediation="Encode output",
        )
        assert finding.confidence == "medium"
