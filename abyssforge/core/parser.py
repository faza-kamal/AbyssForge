"""
AbyssForge Response Parser
Parses HTTP responses to extract useful information for vulnerability detection.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.parser")


class ResponseParser:
    """Parses HTTP responses and extracts relevant data."""

    # Common SQL error patterns
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",
        r"MySqlClient\.",
        r"MySqlException",
        r"supplied argument is not a valid MySQL",
        r"You have an error in your SQL syntax",
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"Warning.*ora_",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"\bSQL Server\b.*\bDriver\b",
        r"Warning.*mssql_",
        r"\bSQL Server\b.*\b(Dialect|Native Client)\b",
        r"ADODB\.Field",
        r"ADODB\.Recordset error",
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"SQLite.*Error",
        r"SQLite3::SQLException",
        r"SQLITE_ERROR",
        r"System\.Data\.SQLite\.SQLiteException",
        r"SQL error.*POS",
    ]

    # Technology fingerprints
    TECH_PATTERNS = {
        "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
        "Drupal": [r"Drupal", r"/sites/default/files", r"/misc/drupal.js"],
        "Joomla": [r"/media/jui/", r"Joomla!", r"/components/com_"],
        "Laravel": [r"laravel_session", r"XSRF-TOKEN", r"Laravel"],
        "Django": [r"csrfmiddlewaretoken", r"Django", r"__admin_media_prefix__"],
        "Ruby on Rails": [r"_rails_", r"X-Powered-By.*Phusion Passenger"],
        "ASP.NET": [r"ASP.NET", r"__VIEWSTATE", r"__EVENTVALIDATION"],
        "PHP": [r"PHPSESSID", r"X-Powered-By.*PHP"],
        "Apache": [r"Server.*Apache"],
        "Nginx": [r"Server.*nginx"],
        "IIS": [r"Server.*Microsoft-IIS"],
        "Express.js": [r"X-Powered-By.*Express"],
        "Spring": [r"JSESSIONID", r"X-Application-Context"],
    }

    def __init__(self, response_text: str, status_code: int, headers: Dict[str, str]) -> None:
        self.text = response_text
        self.status_code = status_code
        self.headers = headers
        self._soup: Optional[BeautifulSoup] = None

    @property
    def soup(self) -> BeautifulSoup:
        """Lazy-initialize BeautifulSoup parser."""
        if self._soup is None:
            self._soup = BeautifulSoup(self.text, "html.parser")
        return self._soup

    def detect_sql_errors(self) -> List[str]:
        """
        Detect SQL error messages in the response.

        Returns:
            List of matched SQL error patterns
        """
        errors = []
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, self.text, re.IGNORECASE):
                errors.append(pattern)
        return errors

    def detect_technologies(self) -> Dict[str, bool]:
        """
        Fingerprint web technologies used by the target.

        Returns:
            Dictionary of technology names and whether they were detected
        """
        detected = {}
        headers_str = " ".join(f"{k}: {v}" for k, v in self.headers.items())
        combined = self.text + headers_str

        for tech, patterns in self.TECH_PATTERNS.items():
            detected[tech] = any(
                re.search(p, combined, re.IGNORECASE) for p in patterns
            )

        return {k: v for k, v in detected.items() if v}

    def extract_forms(self) -> List[Dict[str, Any]]:
        """Extract all HTML forms with their inputs."""
        forms = []

        for form in self.soup.find_all("form"):
            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name", "")
                if name:
                    inputs.append({
                        "name": name,
                        "type": tag.get("type", "text"),
                        "value": tag.get("value", ""),
                        "required": tag.has_attr("required"),
                    })

            forms.append({
                "action": form.get("action", ""),
                "method": form.get("method", "get").upper(),
                "inputs": inputs,
                "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
            })

        return forms

    def extract_links(self, base_url: str) -> List[str]:
        """Extract all hyperlinks from the page."""
        links = set()

        for tag in self.soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                try:
                    absolute = urljoin(base_url, href)
                    if urlparse(absolute).scheme in ("http", "https"):
                        links.add(absolute)
                except Exception:
                    pass

        return list(links)

    def extract_scripts(self) -> List[str]:
        """Extract all JavaScript sources and inline scripts."""
        scripts = []
        for script in self.soup.find_all("script"):
            src = script.get("src")
            if src:
                scripts.append(src)
            elif script.string:
                scripts.append(f"[inline] {script.string[:100]}")
        return scripts

    def check_security_headers(self) -> Dict[str, Dict[str, Any]]:
        """
        Check for security-related HTTP headers.

        Returns:
            Dictionary with header names and their status/values
        """
        security_headers = {
            "Strict-Transport-Security": {
                "present": False,
                "value": None,
                "severity": "high",
                "description": "HSTS not set - site may be vulnerable to downgrade attacks",
            },
            "Content-Security-Policy": {
                "present": False,
                "value": None,
                "severity": "high",
                "description": "CSP not set - may allow XSS attacks",
            },
            "X-Frame-Options": {
                "present": False,
                "value": None,
                "severity": "medium",
                "description": "X-Frame-Options not set - site may be vulnerable to clickjacking",
            },
            "X-Content-Type-Options": {
                "present": False,
                "value": None,
                "severity": "low",
                "description": "X-Content-Type-Options not set - MIME sniffing may be possible",
            },
            "X-XSS-Protection": {
                "present": False,
                "value": None,
                "severity": "low",
                "description": "X-XSS-Protection header not set",
            },
            "Referrer-Policy": {
                "present": False,
                "value": None,
                "severity": "low",
                "description": "Referrer-Policy not set",
            },
            "Permissions-Policy": {
                "present": False,
                "value": None,
                "severity": "info",
                "description": "Permissions-Policy not set",
            },
        }

        lower_headers = {k.lower(): v for k, v in self.headers.items()}

        for header_name, info in security_headers.items():
            value = lower_headers.get(header_name.lower())
            if value:
                info["present"] = True
                info["value"] = value

        return security_headers

    def extract_cookies(self) -> List[Dict[str, Any]]:
        """Extract and analyze cookies from response headers."""
        cookies = []
        set_cookie = self.headers.get("Set-Cookie", "")

        if not set_cookie:
            return cookies

        # Parse cookie attributes
        for cookie_str in set_cookie.split(",\n"):
            parts = cookie_str.strip().split(";")
            if not parts:
                continue

            name_value = parts[0].strip()
            if "=" not in name_value:
                continue

            name, _, value = name_value.partition("=")
            cookie_info = {
                "name": name.strip(),
                "value": value.strip(),
                "httponly": False,
                "secure": False,
                "samesite": None,
                "domain": None,
                "path": None,
            }

            for attr in parts[1:]:
                attr = attr.strip().lower()
                if attr == "httponly":
                    cookie_info["httponly"] = True
                elif attr == "secure":
                    cookie_info["secure"] = True
                elif attr.startswith("samesite="):
                    cookie_info["samesite"] = attr.split("=")[1]
                elif attr.startswith("domain="):
                    cookie_info["domain"] = attr.split("=")[1]
                elif attr.startswith("path="):
                    cookie_info["path"] = attr.split("=")[1]

            cookies.append(cookie_info)

        return cookies

    def find_hidden_inputs(self) -> List[Dict[str, str]]:
        """Find hidden form inputs that might contain tokens."""
        hidden = []
        for inp in self.soup.find_all("input", type="hidden"):
            hidden.append({
                "name": inp.get("name", ""),
                "value": inp.get("value", ""),
            })
        return hidden

    def detect_waf(self) -> Optional[str]:
        """
        Attempt to detect WAF (Web Application Firewall) presence.

        Returns:
            WAF name if detected, None otherwise
        """
        waf_signatures = {
            "Cloudflare": ["__cfduid", "cf-ray", "cloudflare"],
            "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
            "Imperva": ["incap_ses", "visid_incap", "X-Iinfo"],
            "Akamai": ["akamai", "ak_bmsc"],
            "F5 BIG-IP": ["BigIP", "BIGipServer", "F5"],
            "ModSecurity": ["mod_security", "ModSecurity"],
        }

        headers_str = " ".join(f"{k}: {v}" for k, v in self.headers.items()).lower()

        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in headers_str or sig.lower() in self.text.lower():
                    return waf_name

        return None

    def get_server_info(self) -> Dict[str, Optional[str]]:
        """Extract server information from response headers."""
        return {
            "server": self.headers.get("Server"),
            "x_powered_by": self.headers.get("X-Powered-By"),
            "x_aspnet_version": self.headers.get("X-AspNet-Version"),
            "via": self.headers.get("Via"),
        }
