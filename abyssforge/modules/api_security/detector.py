"""
AbyssForge API Security Testing Module
Tests for GraphQL introspection, JWT vulnerabilities, REST API issues, and more.
"""

import base64
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from abyssforge.core.request import RequestHandler
from abyssforge.modules.base import BaseModule, Finding
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.module.api_security")


class APISecurityDetector(BaseModule):
    """API Security Testing Module."""

    MODULE_NAME = "api_security"
    VULN_TYPE = "API Security Issue"
    SEVERITY = "high"
    CWE = "CWE-285"
    DESCRIPTION = "API security issues can expose sensitive data or allow unauthorized access."
    REMEDIATION = "Implement proper authentication, authorization, and input validation for all API endpoints."

    # Common API endpoint paths
    API_PATHS = [
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/v1/",
        "/v2/",
        "/graphql",
        "/graphiql",
        "/api/graphql",
        "/swagger",
        "/swagger-ui",
        "/api-docs",
        "/openapi",
    ]

    # GraphQL introspection query
    GRAPHQL_INTROSPECTION = """
    {
        __schema {
            types {
                name
                kind
                fields {
                    name
                    type {
                        name
                        kind
                    }
                }
            }
        }
    }
    """

    def scan(self, url: str, **kwargs: Any) -> List[Finding]:
        """Scan for API security issues."""
        self.findings = []
        base_url = self._get_base_url(url)

        if self.config.get("graphql", True):
            self._check_graphql(url, base_url)

        if self.config.get("jwt", True):
            self._check_jwt_in_response(url)

        self._check_api_endpoints(base_url)

        return self.findings

    def _get_base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _check_graphql(self, url: str, base_url: str) -> None:
        """Check for exposed GraphQL introspection."""
        graphql_endpoints = [
            url if "graphql" in url.lower() else None,
            urljoin(base_url, "/graphql"),
            urljoin(base_url, "/graphiql"),
            urljoin(base_url, "/api/graphql"),
        ]

        for endpoint in graphql_endpoints:
            if not endpoint:
                continue

            try:
                response = self.request_handler.post(
                    endpoint,
                    json_data={"query": self.GRAPHQL_INTROSPECTION},
                    extra_headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "__schema" in str(data) or "types" in str(data):
                            types = []
                            if isinstance(data, dict) and "data" in data:
                                schema = data["data"].get("__schema", {})
                                types = [t["name"] for t in schema.get("types", [])
                                        if t["name"] and not t["name"].startswith("__")]

                            self.add_finding(
                                url=endpoint,
                                parameter="GraphQL Introspection",
                                payload=self.GRAPHQL_INTROSPECTION.strip()[:100],
                                evidence=f"GraphQL introspection enabled. Found {len(types)} types: {types[:5]}",
                                severity="medium",
                                confidence="high",
                                vuln_type="GraphQL Introspection Enabled",
                                description="GraphQL introspection is enabled, exposing the full API schema.",
                                remediation="Disable GraphQL introspection in production environments.",
                            )
                            return

                    except (json.JSONDecodeError, KeyError):
                        pass

            except Exception as e:
                logger.debug(f"Error checking GraphQL at {endpoint}: {e}")

    def _check_jwt_in_response(self, url: str) -> None:
        """Check for JWT tokens in responses and analyze them."""
        try:
            response = self.request_handler.get(url)

            # Look for JWT patterns in response
            jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
            tokens = re.findall(jwt_pattern, response.text)

            for token in tokens[:3]:  # Analyze first 3 tokens
                analysis = self._analyze_jwt(token)
                if analysis.get("issues"):
                    self.add_finding(
                        url=url,
                        parameter="JWT Token",
                        payload=token[:50] + "...",
                        evidence=f"JWT Issues: {analysis['issues']}",
                        severity="high",
                        confidence="high",
                        vuln_type="JWT Vulnerability",
                        description="JWT token security issues detected.",
                        remediation="Use strong algorithms (RS256/ES256), set expiration, validate all claims.",
                        extra_info={"algorithm": analysis.get("algorithm"), "claims": analysis.get("claims")},
                    )

        except Exception as e:
            logger.debug(f"Error checking JWT: {e}")

    def _analyze_jwt(self, token: str) -> Dict[str, Any]:
        """Analyze JWT token for common vulnerabilities."""
        issues = []
        result: Dict[str, Any] = {}

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return result

            # Decode header (pad if needed)
            header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            algorithm = header.get("alg", "").upper()
            result["algorithm"] = algorithm

            # Decode payload
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
            result["claims"] = claims

            # Check for weak algorithms
            if algorithm == "NONE" or algorithm == "":
                issues.append("Algorithm 'none' - signature not verified!")
            elif algorithm in ("HS256", "HS384", "HS512"):
                issues.append(f"Symmetric algorithm {algorithm} - secret may be guessable")

            # Check for missing expiration
            if "exp" not in claims:
                issues.append("No expiration (exp) claim - token never expires")

            result["issues"] = issues

        except Exception:
            pass

        return result

    def _check_api_endpoints(self, base_url: str) -> None:
        """Probe common API endpoints for exposure."""
        for path in self.API_PATHS:
            try:
                url = urljoin(base_url, path)
                response = self.request_handler.get(url)

                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    if "json" in content_type or "xml" in content_type:
                        # Check if swagger/openapi spec is exposed
                        if any(kw in response.text for kw in ["swagger", "openapi", "paths"]):
                            self.add_finding(
                                url=url,
                                parameter="API Documentation",
                                payload="[Endpoint Discovery]",
                                evidence=f"API documentation exposed at: {url}",
                                severity="medium",
                                confidence="high",
                                vuln_type="API Documentation Exposed",
                                description="API documentation is publicly accessible.",
                                remediation="Restrict access to API documentation in production.",
                            )

            except Exception as e:
                logger.debug(f"Error checking API endpoint {path}: {e}")

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
