"""
AbyssForge Helper Utilities
"""

import hashlib
import time
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def load_payloads(filepath: str) -> List[str]:
    """
    Load payloads from a text file, skipping comments and blank lines.

    Args:
        filepath: Path to payload file

    Returns:
        List of payload strings
    """
    payloads = []
    path = Path(filepath)

    if not path.exists():
        return payloads

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                payloads.append(line)

    return payloads


def get_url_params(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def inject_param(url: str, param: str, value: str) -> str:
    """
    Inject a value into a specific URL parameter.

    Args:
        url: Original URL
        param: Parameter name to inject
        value: Value to inject

    Returns:
        Modified URL string
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def generate_unique_id() -> str:
    """Generate a unique identifier based on timestamp."""
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:12]


def chunk_list(lst: List[Any], size: int) -> Generator[List[Any], None, None]:
    """Split a list into chunks of specified size."""
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def format_bytes(size: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


def calculate_response_time(start: float) -> float:
    """Calculate elapsed time since start in milliseconds."""
    return (time.time() - start) * 1000


def extract_forms(html_content: str) -> List[Dict[str, Any]]:
    """
    Extract HTML forms from page content.

    Args:
        html_content: Raw HTML string

    Returns:
        List of form dictionaries with action, method, and inputs
    """
    from bs4 import BeautifulSoup

    forms = []
    soup = BeautifulSoup(html_content, "html.parser")

    for form in soup.find_all("form"):
        form_data: Dict[str, Any] = {
            "action": form.get("action", ""),
            "method": form.get("method", "get").lower(),
            "inputs": [],
        }

        for inp in form.find_all(["input", "textarea", "select"]):
            input_data = {
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            }
            if input_data["name"]:
                form_data["inputs"].append(input_data)

        forms.append(form_data)

    return forms


def extract_links(html_content: str, base_url: str) -> List[str]:
    """
    Extract all links from HTML content.

    Args:
        html_content: Raw HTML string
        base_url: Base URL for resolving relative links

    Returns:
        List of absolute URL strings
    """
    from urllib.parse import urljoin

    from bs4 import BeautifulSoup

    links = []
    soup = BeautifulSoup(html_content, "html.parser")

    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        if href and not href.startswith(("#", "javascript:", "mailto:")):
            absolute = urljoin(base_url, href)
            if absolute not in links:
                links.append(absolute)

    return links


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same domain."""
    domain1 = urlparse(url1).netloc
    domain2 = urlparse(url2).netloc
    return domain1 == domain2


def severity_score(severity: str) -> int:
    """Convert severity string to numeric score for sorting."""
    scores = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return scores.get(severity.lower(), 0)
