"""
AbyssForge Network Utilities
"""

import socket
from typing import List, Optional
from urllib.parse import urlparse

from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.network")


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_domain_from_url(url: str) -> str:
    """Extract domain/netloc from URL."""
    return urlparse(url).netloc


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def get_common_ports() -> List[int]:
    """Return list of common web application ports."""
    return [80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 5000, 9000]


def scan_ports(host: str, ports: Optional[List[int]] = None, timeout: float = 1.0) -> List[int]:
    """
    Scan for open ports on a host.

    Args:
        host: Target hostname or IP
        ports: List of ports to scan (default: common web ports)
        timeout: Connection timeout per port

    Returns:
        List of open port numbers
    """
    if ports is None:
        ports = get_common_ports()

    open_ports = []
    for port in ports:
        if is_port_open(host, port, timeout):
            open_ports.append(port)
            logger.debug(f"Open port found: {host}:{port}")

    return open_ports
