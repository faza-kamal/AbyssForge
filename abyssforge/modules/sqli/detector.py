"""
AbyssForge SQL Injection Detection Module
Detects various SQL injection vulnerabilities including time-based, boolean-based,
error-based, and union-based SQL injection.
"""

import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from abyssforge.core.parser import ResponseParser
from abyssforge.core.request import RequestHandler
from abyssforge.modules.base import BaseModule, Finding
from abyssforge.utils.helpers import get_url_params, inject_param
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.module.sqli")

PAYLOADS_DIR = Path(__file__).parent.parent.parent / "config" / "payloads"


class SQLiDetector(BaseModule):
    """
    Comprehensive SQL Injection detection module.
    Supports error-based, time-based, boolean-based, and union-based detection.
    """

    MODULE_NAME = "sqli"
    VULN_TYPE = "SQL Injection"
    SEVERITY = "critical"
    CWE = "CWE-89"
    DESCRIPTION = (
        "SQL Injection allows attackers to interfere with database queries. "
        "This can lead to unauthorized data access, modification, or deletion."
    )
    REMEDIATION = (
        "Use parameterized queries or prepared statements. "
        "Apply input validation and use an ORM. "
        "Apply least privilege principles to database accounts."
    )

    # Error patterns indicating SQL injection
    ERROR_PATTERNS = [
        (r"You have an error in your SQL syntax", "MySQL"),
        (r"Warning.*mysql_", "MySQL"),
        (r"MySQLSyntaxErrorException", "MySQL"),
        (r"supplied argument is not a valid MySQL result", "MySQL"),
        (r"check the manual that corresponds to your MySQL server version", "MySQL"),
        (r"ORA-\d{5}", "Oracle"),
        (r"Oracle error", "Oracle"),
        (r"Warning.*oci_", "Oracle"),
        (r"PostgreSQL.*ERROR", "PostgreSQL"),
        (r"Warning.*pg_", "PostgreSQL"),
        (r"ERROR:\s+syntax error at or near", "PostgreSQL"),
        (r"Npgsql\.", "PostgreSQL"),
        (r"Driver.*SQL Server", "MSSQL"),
        (r"OLE DB.*SQL Server", "MSSQL"),
        (r"Unclosed quotation mark", "MSSQL"),
        (r"Warning.*mssql_", "MSSQL"),
        (r"SQLite.*Exception", "SQLite"),
        (r"SQLITE_ERROR", "SQLite"),
        (r"sqlite3\.OperationalError", "SQLite"),
    ]

    # Simple error-triggering payloads
    ERROR_PAYLOADS = ["'", '"', "`", "''", '""']

    # Time-based payloads (delay in seconds)
    TIME_PAYLOADS = [
        ("'; WAITFOR DELAY '0:0:5'--", "MSSQL"),
        ("'; SELECT SLEEP(5)--", "MySQL"),
        ("'; SELECT pg_sleep(5)--", "PostgreSQL"),
        ("' OR SLEEP(5)--", "MySQL"),
        ("1; SELECT SLEEP(5)--", "MySQL"),
        ("1); SELECT SLEEP(5)--", "MySQL"),
        ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "MySQL"),
    ]

    # Boolean-based payloads (true/false pairs)
    BOOLEAN_PAYLOADS = [
        ("' AND 1=1--", "' AND 1=2--"),
        ("' OR 1=1--", "' OR 1=2--"),
        ("1' AND '1'='1", "1' AND '1'='2"),
        ("' AND 'a'='a", "' AND 'a'='b"),
    ]

    # Union-based payloads
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL--",
        "1 UNION SELECT NULL--",
    ]

    def __init__(
        self,
        request_handler: RequestHandler,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(request_handler, config)
        self.time_delay = self.config.get("time_delay", 5)
        self.max_payloads = self.config.get("max_payloads", 50)

    def scan(self, url: str, **kwargs: Any) -> List[Finding]:
        """
        Scan URL for SQL injection vulnerabilities.

        Args:
            url: Target URL with parameters to test

        Returns:
            List of SQLi findings
        """
        self.findings = []
        params = get_url_params(url)

        if not params:
            logger.debug(f"No URL parameters found in: {url}")
            return self.findings

        logger.info(f"Testing {len(params)} parameters for SQLi: {url}")

        for param_name in params:
            if self.config.get("error_based", True):
                self._test_error_based(url, param_name)

            if self.config.get("time_based", True):
                self._test_time_based(url, param_name)

            if self.config.get("boolean_based", True):
                self._test_boolean_based(url, param_name)

            if self.config.get("union_based", True):
                self._test_union_based(url, param_name)

        return self.findings

    def _test_error_based(self, url: str, param: str) -> None:
        """Test for error-based SQL injection."""
        for payload in self.ERROR_PAYLOADS:
            try:
                test_url = inject_param(url, param, payload)
                response = self.request_handler.get(test_url)
                parser = ResponseParser(response.text, response.status_code, dict(response.headers))
                errors = parser.detect_sql_errors()

                if errors:
                    db_type = self._identify_db_from_errors(response.text)
                    self.add_finding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"SQL error detected: {errors[0][:100]}",
                        severity="critical",
                        confidence="high",
                        extra_info={"db_type": db_type, "error_pattern": errors[0]},
                    )
                    return  # Found it, no need to test more payloads

            except Exception as e:
                logger.debug(f"Error testing SQLi payload {payload}: {e}")

    def _test_time_based(self, url: str, param: str) -> None:
        """Test for time-based blind SQL injection."""
        # Get baseline response time
        baseline = self.measure_baseline(url)

        for payload, db_hint in self.TIME_PAYLOADS:
            try:
                test_url = inject_param(url, param, payload)
                start = time.monotonic()
                self.request_handler.get(test_url)
                elapsed = time.monotonic() - start

                # If response took significantly longer than baseline
                if elapsed >= (self.time_delay - 1) and elapsed >= (baseline + self.time_delay - 1):
                    self.add_finding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f}s (baseline: {baseline:.2f}s)",
                        severity="critical",
                        confidence="medium",
                        extra_info={
                            "db_hint": db_hint,
                            "response_time": elapsed,
                            "baseline": baseline,
                        },
                    )
                    return

            except Exception as e:
                logger.debug(f"Error in time-based test: {e}")

    def _test_boolean_based(self, url: str, param: str) -> None:
        """Test for boolean-based blind SQL injection."""
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            try:
                true_url = inject_param(url, param, true_payload)
                false_url = inject_param(url, param, false_payload)

                true_resp = self.request_handler.get(true_url)
                false_resp = self.request_handler.get(false_url)

                # Check if responses differ significantly
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                len_diff = abs(true_len - false_len)

                # Also check status codes
                status_diff = true_resp.status_code != false_resp.status_code

                if status_diff or (len_diff > 50 and true_resp.status_code == 200):
                    self.add_finding(
                        url=url,
                        parameter=param,
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=(
                            f"Response length differs: TRUE={true_len} bytes, "
                            f"FALSE={false_len} bytes (diff: {len_diff})"
                        ),
                        severity="high",
                        confidence="medium",
                        extra_info={
                            "true_length": true_len,
                            "false_length": false_len,
                            "difference": len_diff,
                        },
                    )
                    return

            except Exception as e:
                logger.debug(f"Error in boolean-based test: {e}")

    def _test_union_based(self, url: str, param: str) -> None:
        """Test for union-based SQL injection."""
        for payload in self.UNION_PAYLOADS:
            try:
                test_url = inject_param(url, param, payload)
                response = self.request_handler.get(test_url)

                # Look for indicators of successful UNION injection
                indicators = [
                    "NULL" in response.text and response.status_code == 200,
                    re.search(r"\bUNION\b", response.text, re.IGNORECASE) and "NULL" in response.text,
                ]

                # Check for SQL errors that suggest syntax is close
                parser = ResponseParser(response.text, response.status_code, dict(response.headers))
                errors = parser.detect_sql_errors()

                if any(indicators) and not errors:
                    self.add_finding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="UNION SELECT payload may have succeeded",
                        severity="critical",
                        confidence="low",  # Lower confidence - needs manual verification
                        extra_info={"response_length": len(response.text)},
                    )
                    return

            except Exception as e:
                logger.debug(f"Error in union-based test: {e}")

    def _identify_db_from_errors(self, response_text: str) -> str:
        """Identify database type from error messages."""
        for pattern, db_type in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_type
        return "Unknown"

    def test_post_params(self, url: str, data: Dict[str, str]) -> List[Finding]:
        """
        Test POST parameters for SQL injection.

        Args:
            url: Target URL
            data: POST data dictionary

        Returns:
            List of findings
        """
        self.findings = []

        for param_name in data:
            original_value = data[param_name]

            for payload in self.ERROR_PAYLOADS:
                try:
                    test_data = dict(data)
                    test_data[param_name] = payload

                    response = self.request_handler.post(url, data=test_data)
                    parser = ResponseParser(
                        response.text, response.status_code, dict(response.headers)
                    )
                    errors = parser.detect_sql_errors()

                    if errors:
                        db_type = self._identify_db_from_errors(response.text)
                        self.add_finding(
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"SQL error: {errors[0][:100]}",
                            severity="critical",
                            confidence="high",
                            request_method="POST",
                            extra_info={"db_type": db_type},
                        )
                        break

                except Exception as e:
                    logger.debug(f"Error in POST SQLi test: {e}")

        return self.findings
