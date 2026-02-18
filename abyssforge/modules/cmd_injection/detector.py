"""
AbyssForge Command Injection Detection Module
"""

import re
import time
from typing import Any, Dict, List, Optional

from abyssforge.core.request import RequestHandler
from abyssforge.modules.base import BaseModule, Finding
from abyssforge.utils.helpers import get_url_params, inject_param
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.module.cmd_injection")


class CMDInjectionDetector(BaseModule):
    """OS Command Injection Detection Module."""

    MODULE_NAME = "cmd_injection"
    VULN_TYPE = "Command Injection"
    SEVERITY = "critical"
    CWE = "CWE-78"
    DESCRIPTION = (
        "Command injection allows attackers to execute arbitrary OS commands "
        "on the server, potentially leading to complete system compromise."
    )
    REMEDIATION = (
        "Never pass user input directly to OS commands. "
        "Use safe APIs instead of shell functions. "
        "Validate and sanitize all user input using allowlists."
    )

    # Time-based payloads (sleep for 5 seconds)
    TIME_PAYLOADS = [
        ";sleep 5",
        "||sleep 5",
        "|sleep 5",
        "&sleep 5",
        "&&sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        ";sleep 5;",
        "; sleep 5 #",
        "& ping -c 5 127.0.0.1 &",
        # Windows
        "; timeout 5",
        "| timeout 5",
        "& timeout 5",
        "&& timeout 5",
        "; ping -n 5 127.0.0.1",
    ]

    # Response-based patterns that indicate command execution
    OUTPUT_PATTERNS = [
        r"uid=\d+\(\w+\)",  # Unix id command
        r"root:x:0:0:",      # /etc/passwd
        r"Windows \w+ Version",
        r"Microsoft Windows",
        r"Volume in drive",  # Windows dir command
        r"\[extensions\]",   # win.ini
    ]

    def scan(self, url: str, **kwargs: Any) -> List[Finding]:
        """Scan for command injection vulnerabilities."""
        self.findings = []
        params = get_url_params(url)

        if not params:
            return self.findings

        logger.info(f"Testing {len(params)} parameters for command injection: {url}")

        for param in params:
            self._test_time_based(url, param)

        return self.findings

    def _test_time_based(self, url: str, param: str) -> None:
        """Test for time-based blind command injection."""
        baseline = self.measure_baseline(url)

        for payload in self.TIME_PAYLOADS:
            try:
                test_url = inject_param(url, param, payload)
                start = time.monotonic()
                self.request_handler.get(test_url)
                elapsed = time.monotonic() - start

                if elapsed >= 4.5 and elapsed >= (baseline + 4):
                    self.add_finding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Response delayed {elapsed:.2f}s (baseline: {baseline:.2f}s)",
                        severity="critical",
                        confidence="medium",
                        extra_info={"response_time": elapsed, "baseline": baseline},
                    )
                    return

            except Exception as e:
                logger.debug(f"Error testing cmd injection: {e}")
