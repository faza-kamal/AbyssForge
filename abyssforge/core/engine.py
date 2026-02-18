"""
AbyssForge Scanning Engine
Orchestrates all vulnerability modules and manages the scanning lifecycle.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type
from urllib.parse import urlparse

from abyssforge.core.parser import ResponseParser
from abyssforge.core.request import RequestHandler
from abyssforge.modules.api_security.detector import APISecurityDetector
from abyssforge.modules.base import BaseModule, Finding
from abyssforge.modules.cmd_injection.detector import CMDInjectionDetector
from abyssforge.modules.csrf.detector import CSRFDetector
from abyssforge.modules.lfi.detector import LFIDetector
from abyssforge.modules.misconfig.detector import MisconfigDetector
from abyssforge.modules.sqli.detector import SQLiDetector
from abyssforge.modules.xss.detector import XSSDetector
from abyssforge.utils.helpers import extract_forms, extract_links, is_same_domain
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.engine")


@dataclass
class ScanResult:
    """Complete scan result containing all findings."""

    target_url: str
    scan_id: str
    start_time: float
    end_time: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    urls_scanned: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    technologies: Dict[str, bool] = field(default_factory=dict)
    waf_detected: Optional[str] = None

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration,
            "urls_scanned": len(self.urls_scanned),
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts,
            "technologies": self.technologies,
            "waf_detected": self.waf_detected,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


class ScanEngine:
    """
    Core scanning engine that orchestrates vulnerability detection modules.
    """

    # Available modules
    MODULES: Dict[str, Type[BaseModule]] = {
        "sqli": SQLiDetector,
        "xss": XSSDetector,
        "csrf": CSRFDetector,
        "lfi": LFIDetector,
        "cmd_injection": CMDInjectionDetector,
        "misconfig": MisconfigDetector,
        "api_security": APISecurityDetector,
    }

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        Initialize the scanning engine.

        Args:
            config: Global configuration dictionary
        """
        self.config = config
        self.scanner_config = config.get("scanner", {})
        self.modules_config = config.get("modules", {})

        # Initialize request handler
        proxy_config = config.get("proxy", {})
        proxy = None
        if proxy_config.get("enabled"):
            proxy = proxy_config.get("http") or proxy_config.get("socks")

        self.request_handler = RequestHandler(
            timeout=self.scanner_config.get("timeout", 30),
            max_retries=self.scanner_config.get("max_retries", 3),
            retry_delay=self.scanner_config.get("retry_delay", 1.0),
            proxy=proxy,
            headers=config.get("headers", {}).get("default"),
            verify_ssl=self.scanner_config.get("verify_ssl", False),
            rate_limit=self.scanner_config.get("rate_limit", 10.0),
        )

        # Initialize enabled modules
        self.active_modules: List[BaseModule] = self._initialize_modules()

        logger.info(f"Initialized {len(self.active_modules)} scanning modules")

    def _initialize_modules(self) -> List[BaseModule]:
        """Initialize all enabled vulnerability modules."""
        modules = []

        for module_name, module_class in self.MODULES.items():
            module_config = self.modules_config.get(module_name, {})
            if module_config.get("enabled", True):
                try:
                    module = module_class(
                        request_handler=self.request_handler,
                        config=module_config,
                    )
                    modules.append(module)
                    logger.debug(f"Loaded module: {module_name}")
                except Exception as e:
                    logger.error(f"Failed to load module {module_name}: {e}")

        return modules

    def scan(
        self,
        url: str,
        crawl: bool = False,
        max_depth: int = 2,
        scan_id: Optional[str] = None,
    ) -> ScanResult:
        """
        Perform a full vulnerability scan.

        Args:
            url: Target URL to scan
            crawl: Whether to crawl the site for additional URLs
            max_depth: Maximum crawl depth
            scan_id: Optional scan identifier

        Returns:
            ScanResult object with all findings
        """
        from abyssforge.utils.helpers import generate_unique_id

        scan_id = scan_id or generate_unique_id()
        result = ScanResult(
            target_url=url,
            scan_id=scan_id,
            start_time=time.time(),
        )

        logger.info(f"Starting scan {scan_id} on: {url}")

        # Collect URLs to scan
        urls_to_scan = [url]

        if crawl:
            logger.info(f"Crawling site (max depth: {max_depth})...")
            crawled = self._crawl(url, max_depth)
            urls_to_scan.extend(crawled)
            logger.info(f"Found {len(crawled)} additional URLs")

        # Perform initial tech detection
        try:
            response = self.request_handler.get(url)
            parser = ResponseParser(response.text, response.status_code, dict(response.headers))
            result.technologies = parser.detect_technologies()
            result.waf_detected = parser.detect_waf()

            if result.waf_detected:
                logger.warning(f"WAF detected: {result.waf_detected}")
            if result.technologies:
                logger.info(f"Technologies detected: {list(result.technologies.keys())}")

        except Exception as e:
            logger.error(f"Initial probe failed: {e}")
            result.errors.append(str(e))

        # Scan each URL with all modules
        threads = self.scanner_config.get("threads", 10)
        with ThreadPoolExecutor(max_workers=min(threads, len(urls_to_scan))) as executor:
            futures = {
                executor.submit(self._scan_url, scan_url): scan_url
                for scan_url in urls_to_scan
            }

            for future, scan_url in futures.items():
                try:
                    url_findings = future.result()
                    result.findings.extend(url_findings)
                    result.urls_scanned.append(scan_url)
                except Exception as e:
                    logger.error(f"Error scanning {scan_url}: {e}")
                    result.errors.append(f"{scan_url}: {e}")

        result.end_time = time.time()

        # Summary
        logger.info(
            f"Scan complete! Duration: {result.duration:.1f}s | "
            f"URLs: {len(result.urls_scanned)} | "
            f"Findings: {len(result.findings)} | "
            f"Critical: {result.severity_counts.get('critical', 0)} | "
            f"High: {result.severity_counts.get('high', 0)}"
        )

        return result

    def _scan_url(self, url: str) -> List[Finding]:
        """Scan a single URL with all active modules."""
        all_findings = []

        for module in self.active_modules:
            if not module.enabled:
                continue

            try:
                logger.debug(f"Running {module.MODULE_NAME} on {url}")
                findings = module.scan(url)
                all_findings.extend(findings)
            except Exception as e:
                logger.error(f"Module {module.MODULE_NAME} error on {url}: {e}")

        return all_findings

    def _crawl(self, start_url: str, max_depth: int) -> List[str]:
        """
        Crawl site to discover URLs.

        Args:
            start_url: Starting URL
            max_depth: Maximum crawl depth

        Returns:
            List of discovered URLs
        """
        visited = {start_url}
        to_visit = [(start_url, 0)]
        discovered = []

        while to_visit:
            current_url, depth = to_visit.pop(0)

            if depth >= max_depth:
                continue

            try:
                response = self.request_handler.get(current_url)
                links = extract_links(response.text, current_url)

                for link in links:
                    if link not in visited and is_same_domain(start_url, link):
                        visited.add(link)
                        to_visit.append((link, depth + 1))
                        discovered.append(link)

            except Exception as e:
                logger.debug(f"Crawl error at {current_url}: {e}")

        return discovered[:200]  # Limit to 200 URLs

    def scan_single_module(
        self, url: str, module_name: str
    ) -> List[Finding]:
        """
        Run a single vulnerability module against a URL.

        Args:
            url: Target URL
            module_name: Name of module to run

        Returns:
            List of findings
        """
        module_class = self.MODULES.get(module_name)
        if not module_class:
            raise ValueError(f"Unknown module: {module_name}. Available: {list(self.MODULES.keys())}")

        module_config = self.modules_config.get(module_name, {})
        module = module_class(self.request_handler, module_config)

        return module.scan(url)

    def get_module_list(self) -> List[Dict[str, str]]:
        """Get list of available modules."""
        return [
            {
                "name": module_class.MODULE_NAME,
                "vuln_type": module_class.VULN_TYPE,
                "severity": module_class.SEVERITY,
                "cwe": module_class.CWE or "N/A",
            }
            for module_class in self.MODULES.values()
        ]

    def close(self) -> None:
        """Clean up resources."""
        self.request_handler.close()
