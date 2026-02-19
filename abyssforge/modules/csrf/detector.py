"""
AbyssForge CSRF Detection Module
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from abyssforge.core.parser import ResponseParser
from abyssforge.core.request import RequestHandler
from abyssforge.modules.base import BaseModule, Finding
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.module.csrf")


class CSRFDetector(BaseModule):
    """CSRF Vulnerability Detection Module."""

    MODULE_NAME = "csrf"
    VULN_TYPE = "Cross-Site Request Forgery (CSRF)"
    SEVERITY = "high"
    CWE = "CWE-352"
    DESCRIPTION = (
        "CSRF forces authenticated users to perform unwanted actions. "
        "If the application doesn't properly validate CSRF tokens, "
        "attackers can forge requests on behalf of victims."
    )
    REMEDIATION = (
        "Implement CSRF tokens in all state-changing requests. "
        "Use SameSite cookie attribute. "
        "Validate the Origin/Referer headers server-side."
    )

    # Common CSRF token field names
    TOKEN_NAMES = [
        "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
        "_token", "authenticity_token", "token", "form_token",
        "__requestverificationtoken", "__csrf_token", "xsrf-token",
        "_csrf", "ant[token]", "csrf-token",
    ]

    def scan(self, url: str, **kwargs: Any) -> List[Finding]:
        """Scan for CSRF vulnerabilities in forms."""
        self.findings = []

        try:
            response = self.request_handler.get(url)
            parser = ResponseParser(response.text, response.status_code, dict(response.headers))
            forms = parser.extract_forms()

            for form in forms:
                if form["method"].upper() in ("POST", "PUT", "DELETE", "PATCH"):
                    self._analyze_form(url, form, response.text)

            self._check_cookie_samesite(url, response)

        except Exception as e:
            logger.debug(f"Error in CSRF scan: {e}")

        return self.findings

    def _analyze_form(self, url: str, form: Dict[str, Any], page_content: str) -> None:
        """Analyze a form for CSRF protection."""
        input_names = [i["name"].lower() for i in form.get("inputs", [])]

        # Check if any CSRF token field is present
        has_token = any(
            any(token_name in name for token_name in self.TOKEN_NAMES)
            for name in input_names
        )

        if not has_token:
            action = form.get("action", url)
            self.add_finding(
                url=url,
                parameter=f"Form: {action}",
                payload="[CSRF Analysis]",
                evidence=f"State-changing form ({form['method']}) without CSRF token. Fields: {input_names}",
                severity="high",
                confidence="medium",
                extra_info={
                    "form_action": action,
                    "form_method": form["method"],
                    "form_fields": input_names,
                },
            )

    def _check_cookie_samesite(self, url: str, response: Any) -> None:
        """Check cookie SameSite attribute."""
        parser = ResponseParser(response.text, response.status_code, dict(response.headers))
        cookies = parser.extract_cookies()

        for cookie in cookies:
            if not cookie.get("samesite"):
                if "session" in cookie["name"].lower() or "auth" in cookie["name"].lower():
                    self.add_finding(
                        url=url,
                        parameter=f"Cookie: {cookie['name']}",
                        payload="[Cookie Analysis]",
                        evidence=f"Session cookie '{cookie['name']}' lacks SameSite attribute",
                        severity="medium",
                        confidence="high",
                        vuln_type="Missing SameSite Cookie Attribute",
                        description="Session cookies without SameSite attribute are vulnerable to CSRF attacks.",
                        remediation="Set SameSite=Strict or SameSite=Lax on all session cookies.",
                    )

    def add_finding(self, url, parameter, payload, evidence, severity=None,
                    confidence="medium", request_method="GET", extra_info=None,
                    vuln_type=None, description=None, remediation=None):
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
        self.logger.warning(f"[{finding.severity.upper()}] {finding.vuln_type} at {url}")
        return finding
