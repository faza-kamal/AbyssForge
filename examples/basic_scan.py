"""
AbyssForge - Basic Scan Example

This example demonstrates how to use AbyssForge programmatically
to scan a target URL for web vulnerabilities.

IMPORTANT: Only scan targets you have explicit permission to test.
Unauthorized scanning is illegal.
"""

from abyssforge.core.engine import ScanEngine
from abyssforge.reporters.json_reporter import JSONReporter
from abyssforge.reporters.html_reporter import HTMLReporter

# Configuration
config = {
    "scanner": {
        "threads": 5,
        "timeout": 30,
        "max_retries": 3,
        "retry_delay": 1.0,
        "rate_limit": 5.0,  # 5 requests per second
        "verify_ssl": False,
    },
    "modules": {
        "sqli": {"enabled": True, "time_delay": 5},
        "xss": {"enabled": True, "max_payloads": 20},
        "csrf": {"enabled": True},
        "lfi": {"enabled": True},
        "cmd_injection": {"enabled": True},
        "misconfig": {"enabled": True, "check_sensitive_files": True},
        "api_security": {"enabled": True},
    },
    "proxy": {"enabled": False},
    "headers": {
        "default": {
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        }
    },
}

# Target URL - replace with your authorized target
# DO NOT SCAN TARGETS WITHOUT PERMISSION
TARGET_URL = "http://testphp.vulnweb.com/artists.php?artist=1"  # Example: OWASP test site

def run_basic_scan():
    """Run a basic vulnerability scan."""
    print(f"[*] Initializing AbyssForge scanner...")
    print(f"[*] Target: {TARGET_URL}")
    print(f"[!] Ensure you have authorization to test this target!\n")

    # Initialize engine
    engine = ScanEngine(config)

    # Run scan
    print("[*] Starting scan...")
    result = engine.scan(TARGET_URL, crawl=False)

    # Display summary
    counts = result.severity_counts
    print(f"\n[+] Scan Complete!")
    print(f"    Duration: {result.duration:.1f}s")
    print(f"    URLs Scanned: {len(result.urls_scanned)}")
    print(f"    Total Findings: {len(result.findings)}")
    print(f"    Critical: {counts.get('critical', 0)}")
    print(f"    High:     {counts.get('high', 0)}")
    print(f"    Medium:   {counts.get('medium', 0)}")
    print(f"    Low:      {counts.get('low', 0)}")

    # Show findings
    if result.findings:
        print("\n[+] Vulnerabilities Found:")
        for finding in result.findings:
            print(f"    [{finding.severity.upper()}] {finding.vuln_type}")
            print(f"         URL: {finding.url}")
            print(f"         Param: {finding.parameter}")
            print(f"         Evidence: {finding.evidence[:80]}")
            print()

    # Generate reports
    json_reporter = JSONReporter("output")
    html_reporter = HTMLReporter("output")

    json_path = json_reporter.generate(result)
    html_path = html_reporter.generate(result)

    print(f"[+] Reports saved:")
    print(f"    JSON: {json_path}")
    print(f"    HTML: {html_path}")

    engine.close()
    return result


def run_targeted_scan():
    """Run a targeted scan with specific modules only."""
    engine = ScanEngine(config)

    print("[*] Running targeted SQLi scan...")
    findings = engine.scan_single_module(TARGET_URL, "sqli")

    for finding in findings:
        print(f"[FOUND] {finding.vuln_type} in '{finding.parameter}'")
        print(f"        Evidence: {finding.evidence}")

    engine.close()


if __name__ == "__main__":
    run_basic_scan()
