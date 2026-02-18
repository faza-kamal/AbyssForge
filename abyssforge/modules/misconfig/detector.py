"""
AbyssForge Security Misconfiguration Detection Module
Detects various security misconfigurations including exposed files,
missing security headers, directory listing, CORS issues, and more.
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from abyssforge.core.parser import ResponseParser
from abyssforge.core.request import RequestHandler
from abyssforge.modules.base import BaseModule, Finding
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.module.misconfig")


class MisconfigDetector(BaseModule):
    """Detects common security misconfigurations."""

    MODULE_NAME = "misconfig"
    VULN_TYPE = "Security Misconfiguration"
    SEVERITY = "medium"
    CWE = "CWE-16"
    DESCRIPTION = "Security misconfiguration allows attackers to gain unauthorized access."
    REMEDIATION = "Follow security hardening guides and regularly audit your configuration."

    # Sensitive files/paths to check for exposure
    SENSITIVE_FILES = [
        ".git/HEAD",
        ".git/config",
        ".env",
        ".env.backup",
        ".env.local",
        ".env.production",
        ".htaccess",
        ".htpasswd",
        "wp-config.php",
        "wp-config.php.bak",
        "web.config",
        "config.php",
        "database.php",
        "db.php",
        "config.yml",
        "config.yaml",
        "settings.py",
        "local_settings.py",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "README.md",
        "CHANGELOG.md",
        "backup.sql",
        "dump.sql",
        "db.sql",
        "database.sql",
        "phpinfo.php",
        "info.php",
        "test.php",
        "admin.php",
        "login.php.bak",
        "robots.txt",
        "sitemap.xml",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        "server-status",
        "server-info",
        ".DS_Store",
        "Thumbs.db",
        "composer.json",
        "composer.lock",
        "package.json",
        "package-lock.json",
        "Gemfile",
        "Gemfile.lock",
        "requirements.txt",
        "swagger.json",
        "swagger.yaml",
        "openapi.json",
        "openapi.yaml",
        "api-docs",
    ]

    # Directories that should not be listable
    SENSITIVE_DIRS = [
        "/admin/",
        "/administrator/",
        "/backup/",
        "/backups/",
        "/config/",
        "/configs/",
        "/database/",
        "/db/",
        "/logs/",
        "/log/",
        "/tmp/",
        "/temp/",
        "/uploads/",
        "/upload/",
        "/files/",
        "/data/",
        "/include/",
        "/includes/",
        "/private/",
        "/secret/",
        "/test/",
        "/testing/",
        "/dev/",
        "/development/",
        "/src/",
        "/source/",
        "/old/",
        "/bak/",
        "/cache/",
    ]

    def __init__(
        self,
        request_handler: RequestHandler,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(request_handler, config)

    def scan(self, url: str, **kwargs: Any) -> List[Finding]:
        """
        Scan for security misconfigurations.

        Args:
            url: Target URL

        Returns:
            List of findings
        """
        self.findings = []
        base_url = self._get_base_url(url)

        logger.info(f"Scanning for misconfigurations: {base_url}")

        if self.config.get("check_headers", True):
            self._check_security_headers(url)

        if self.config.get("check_sensitive_files", True):
            self._check_sensitive_files(base_url)

        if self.config.get("check_directory_listing", True):
            self._check_directory_listing(base_url)

        if self.config.get("check_cors", True):
            self._check_cors(url)

        self._check_information_disclosure(url)

        return self.findings

    def _get_base_url(self, url: str) -> str:
        """Extract base URL (scheme + netloc)."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _check_security_headers(self, url: str) -> None:
        """Check for missing or misconfigured security headers."""
        try:
            response = self.request_handler.get(url)
            parser = ResponseParser(response.text, response.status_code, dict(response.headers))
            header_status = parser.check_security_headers()

            for header_name, info in header_status.items():
                if not info["present"]:
                    self.add_finding(
                        url=url,
                        parameter=f"Header: {header_name}",
                        payload="[Header Analysis]",
                        evidence=f"Security header '{header_name}' is not set",
                        severity=info["severity"],
                        confidence="high",
                        vuln_type="Missing Security Header",
                        description=info["description"],
                        remediation=f"Add the '{header_name}' HTTP response header.",
                    )

        except Exception as e:
            logger.debug(f"Error checking security headers: {e}")

    def _check_sensitive_files(self, base_url: str) -> None:
        """Check for exposed sensitive files."""
        for filepath in self.SENSITIVE_FILES:
            try:
                test_url = urljoin(base_url + "/", filepath)
                response = self.request_handler.get(test_url)

                if response.status_code == 200 and len(response.text) > 10:
                    # Additional check to avoid false positives
                    if not self._is_likely_redirect(response):
                        severity = self._get_file_severity(filepath)
                        self.add_finding(
                            url=test_url,
                            parameter=filepath,
                            payload="[File Enumeration]",
                            evidence=f"File accessible: HTTP {response.status_code}, "
                                     f"{len(response.text)} bytes",
                            severity=severity,
                            confidence="high",
                            vuln_type="Sensitive File Exposure",
                            description=f"Sensitive file '{filepath}' is publicly accessible.",
                            remediation=f"Restrict access to '{filepath}' via web server configuration.",
                        )

            except Exception as e:
                logger.debug(f"Error checking {filepath}: {e}")

    def _check_directory_listing(self, base_url: str) -> None:
        """Check if directory listing is enabled."""
        for directory in self.SENSITIVE_DIRS:
            try:
                test_url = urljoin(base_url, directory)
                response = self.request_handler.get(test_url)

                if response.status_code == 200:
                    # Check for directory listing indicators
                    indicators = [
                        "Index of /",
                        "Directory listing for",
                        "Parent Directory",
                        '<a href="?C=N',  # Apache sorting
                        "Last modified",
                    ]

                    if any(ind in response.text for ind in indicators):
                        self.add_finding(
                            url=test_url,
                            parameter=directory,
                            payload="[Directory Listing]",
                            evidence=f"Directory listing enabled for: {directory}",
                            severity="medium",
                            confidence="high",
                            vuln_type="Directory Listing Enabled",
                            description=f"Directory listing is enabled for '{directory}'.",
                            remediation="Disable directory listing in web server configuration (Options -Indexes for Apache).",
                        )

            except Exception as e:
                logger.debug(f"Error checking directory {directory}: {e}")

    def _check_cors(self, url: str) -> None:
        """Check for CORS misconfigurations."""
        try:
            # Test with arbitrary origin
            test_origin = "https://evil.attacker.com"
            response = self.request_handler.get(
                url,
                extra_headers={
                    "Origin": test_origin,
                    "Access-Control-Request-Method": "GET",
                },
            )

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "false")

            if acao == "*":
                self.add_finding(
                    url=url,
                    parameter="CORS",
                    payload=f"Origin: {test_origin}",
                    evidence=f"Access-Control-Allow-Origin: *",
                    severity="low",
                    confidence="high",
                    vuln_type="CORS Misconfiguration",
                    description="CORS allows all origins (*). This may expose APIs to unauthorized domains.",
                    remediation="Restrict CORS to specific trusted origins.",
                )
            elif acao == test_origin:
                severity = "high" if acac.lower() == "true" else "medium"
                self.add_finding(
                    url=url,
                    parameter="CORS",
                    payload=f"Origin: {test_origin}",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    severity=severity,
                    confidence="high",
                    vuln_type="CORS Misconfiguration - Origin Reflection",
                    description="Server reflects arbitrary Origin in CORS response.",
                    remediation="Whitelist only specific trusted origins.",
                )

        except Exception as e:
            logger.debug(f"Error checking CORS: {e}")

    def _check_information_disclosure(self, url: str) -> None:
        """Check for information disclosure in headers and response."""
        try:
            response = self.request_handler.get(url)
            parser = ResponseParser(response.text, response.status_code, dict(response.headers))
            server_info = parser.get_server_info()

            for header, value in server_info.items():
                if value:
                    self.add_finding(
                        url=url,
                        parameter=f"Header: {header}",
                        payload="[Header Analysis]",
                        evidence=f"{header}: {value}",
                        severity="info",
                        confidence="high",
                        vuln_type="Information Disclosure",
                        description=f"Server reveals version information via '{header}' header.",
                        remediation=f"Remove or obfuscate the '{header}' response header.",
                    )

        except Exception as e:
            logger.debug(f"Error checking information disclosure: {e}")

    def _is_likely_redirect(self, response: Any) -> bool:
        """Check if response is likely a redirect/error page."""
        # Check if response length is suspiciously small (custom 404 with 200 status)
        if len(response.text) < 100:
            return True

        # Check for common redirect/error indicators
        error_patterns = [
            "404", "Not Found", "Page Not Found",
            "Error 404", "file not found"
        ]
        return any(p.lower() in response.text.lower() for p in error_patterns)

    def _get_file_severity(self, filepath: str) -> str:
        """Determine severity based on file type."""
        critical_files = {".env", ".git/config", "wp-config.php", ".htpasswd",
                         "database.php", "settings.py", "config.php", "db.php"}
        high_files = {"backup.sql", "dump.sql", "db.sql", "phpinfo.php",
                     ".git/HEAD", "web.config", "docker-compose.yml"}

        for f in critical_files:
            if f in filepath:
                return "critical"
        for f in high_files:
            if f in filepath:
                return "high"
        return "medium"

    def add_finding(self, url, parameter, payload, evidence, severity=None,
                    confidence="medium", request_method="GET", extra_info=None,
                    vuln_type=None, description=None, remediation=None):
        """Override to support custom vuln_type, description, and remediation."""
        finding = Finding(
            vuln_type=vuln_type or self.VULN_TYPE,
            url=url,
            parameter=parameter,
            payload=payload,
            severity=severity or self.SEVERITY,
            evidence=evidence,
            description=description or self.DESCRIPTION,
            remediation=remediation or self.REMEDIATION,
            cwe=self.CWE,
            confidence=confidence,
            request_method=request_method,
            extra_info=extra_info or {},
        )
        self.findings.append(finding)
        self.logger.warning(
            f"[{finding.severity.upper()}] {finding.vuln_type} at {url}"
        )
        return finding
