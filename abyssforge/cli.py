"""
AbyssForge CLI Interface
Command-line interface built with Click.
"""

import sys
from pathlib import Path
from typing import Optional, Tuple

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from abyssforge import __version__

console = Console()

BANNER = r"""
    _   _                     _____
   / \ | |__  _   _ ___ ___ |  ___|__  _ __ __ _  ___
  / _ \| '_ \| | | / __/ __|| |_ / _ \| '__/ _` |/ _ \
 / ___ \ |_) | |_| \__ \__ \|  _| (_) | | | (_| |  __/
/_/   \_\_.__/ \__, |___/___/|_|  \___/|_|  \__, |\___|
               |___/                         |___/
"""


def print_banner() -> None:
    """Print AbyssForge ASCII banner."""
    console.print(f"[bold cyan]{BANNER}[/]")
    console.print(
        f"[dim]  Web Vulnerability Scanner v{__version__} | "
        f"github.com/faza-kamal/AbyssForge[/]\n"
    )
    console.print(
        Panel(
            "[bold yellow]⚠️  LEGAL DISCLAIMER[/]\n"
            "[dim]This tool is for authorized security testing ONLY.\n"
            "Always obtain written permission before testing any system.\n"
            "Unauthorized use is illegal and unethical.[/]",
            border_style="yellow",
        )
    )
    console.print()


def load_config(config_path: Optional[str] = None) -> dict:
    """Load configuration from YAML file."""
    default_config = Path(__file__).parent.parent / "config" / "default_config.yaml"

    if config_path:
        cfg_file = Path(config_path)
    else:
        cfg_file = default_config

    if cfg_file.exists():
        with open(cfg_file) as f:
            return yaml.safe_load(f) or {}
    return {}


@click.group()
@click.version_option(version=__version__, prog_name="AbyssForge")
def cli() -> None:
    """
    AbyssForge - Web Vulnerability Scanner

    A powerful security testing tool for bug bounty hunters and penetration testers.
    """
    pass


@cli.command()
@click.argument("url")
@click.option(
    "--modules", "-m",
    default="all",
    help="Comma-separated modules to run (sqli,xss,csrf,lfi,cmd_injection,misconfig,api_security) or 'all'",
)
@click.option("--threads", "-t", default=10, type=int, help="Number of threads (default: 10)")
@click.option("--timeout", default=30, type=int, help="Request timeout in seconds (default: 30)")
@click.option("--proxy", "-p", default=None, help="Proxy URL (e.g., http://127.0.0.1:8080)")
@click.option("--cookie", "-c", default=None, help="Cookie string (name=value; name2=value2)")
@click.option("--header", "-H", multiple=True, help="Custom header (name:value). Can specify multiple.")
@click.option("--output", "-o", default="output", help="Output directory (default: output)")
@click.option(
    "--format", "-f", "output_format",
    default="json,html",
    help="Output formats: json,html,markdown,csv (default: json,html)",
)
@click.option("--crawl", is_flag=True, help="Crawl the website for additional URLs")
@click.option("--depth", default=2, type=int, help="Crawl depth (default: 2)")
@click.option("--rate-limit", default=10.0, type=float, help="Max requests per second (default: 10)")
@click.option("--config", default=None, help="Path to custom config YAML file")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner and non-essential output")
@click.option("--no-verify-ssl", is_flag=True, help="Disable SSL certificate verification")
def scan(
    url: str,
    modules: str,
    threads: int,
    timeout: int,
    proxy: Optional[str],
    cookie: Optional[str],
    header: Tuple[str, ...],
    output: str,
    output_format: str,
    crawl: bool,
    depth: int,
    rate_limit: float,
    config: Optional[str],
    verbose: bool,
    quiet: bool,
    no_verify_ssl: bool,
) -> None:
    """
    Scan a target URL for web vulnerabilities.

    URL: Target URL to scan (e.g., https://example.com?id=1)

    Examples:

    \b
    # Basic scan
    abyssforge scan https://example.com?id=1

    \b
    # SQLi and XSS only
    abyssforge scan https://example.com?id=1 -m sqli,xss

    \b
    # Full scan with crawling and custom output
    abyssforge scan https://example.com --crawl --depth 3 -o reports -f json,html

    \b
    # Use with proxy (Burp Suite)
    abyssforge scan https://example.com -p http://127.0.0.1:8080 --no-verify-ssl

    \b
    # With authentication
    abyssforge scan https://example.com -c "session=abc123" -H "Authorization: Bearer token"
    """
    if not quiet:
        print_banner()

    # Validate URL
    try:
        from abyssforge.utils.validators import validate_url
        url = validate_url(url)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        sys.exit(1)

    # Load config
    cfg = load_config(config)

    # Override config with CLI options
    cfg.setdefault("scanner", {})
    cfg["scanner"]["threads"] = threads
    cfg["scanner"]["timeout"] = timeout
    cfg["scanner"]["rate_limit"] = rate_limit
    cfg["scanner"]["verify_ssl"] = not no_verify_ssl

    # Process proxy
    if proxy:
        cfg["proxy"] = {"enabled": True, "http": proxy, "https": proxy}

    # Process cookies
    if cookie:
        cookies = {}
        for part in cookie.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, val = part.partition("=")
                cookies[name.strip()] = val.strip()
        cfg["cookies"] = cookies

    # Process custom headers
    if header:
        extra_headers = {}
        for h in header:
            if ":" in h:
                name, _, val = h.partition(":")
                extra_headers[name.strip()] = val.strip()
        cfg.setdefault("headers", {}).setdefault("default", {}).update(extra_headers)

    # Process modules selection
    available_modules = ["sqli", "xss", "csrf", "lfi", "cmd_injection", "misconfig", "api_security"]
    if modules.lower() != "all":
        selected = [m.strip() for m in modules.split(",")]
        invalid = [m for m in selected if m not in available_modules]
        if invalid:
            console.print(f"[red]Invalid modules: {invalid}. Available: {available_modules}[/]")
            sys.exit(1)
        # Disable unselected modules
        for mod in available_modules:
            cfg.setdefault("modules", {}).setdefault(mod, {})["enabled"] = mod in selected
    else:
        selected = available_modules

    # Set logging level
    import logging
    log_level = "DEBUG" if verbose else "INFO"
    from abyssforge.utils.logger import setup_logger
    setup_logger(level=log_level)

    console.print(f"[bold green]Target:[/] {url}")
    console.print(f"[bold green]Modules:[/] {', '.join(selected)}")
    console.print(f"[bold green]Threads:[/] {threads} | [bold green]Timeout:[/] {timeout}s")
    if proxy:
        console.print(f"[bold green]Proxy:[/] {proxy}")
    console.print()

    # Run scan
    try:
        from abyssforge.core.engine import ScanEngine

        with console.status("[bold yellow]Initializing scanner...[/]"):
            engine = ScanEngine(cfg)

        console.print("[bold yellow]Scanning in progress...[/]\n")

        result = engine.scan(url, crawl=crawl, max_depth=depth)

        engine.close()

        # Display results table
        _display_results(result)

        # Generate reports
        formats = [f.strip() for f in output_format.split(",")]
        report_paths = _generate_reports(result, output, formats)

        console.print("\n[bold green]Reports saved:[/]")
        for path in report_paths:
            console.print(f"  [cyan]→ {path}[/]")

        # Exit with non-zero if critical/high findings
        critical_count = result.severity_counts.get("critical", 0)
        high_count = result.severity_counts.get("high", 0)
        if critical_count > 0:
            sys.exit(2)  # Critical findings
        elif high_count > 0:
            sys.exit(1)  # High findings

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Scan error: {e}[/]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _display_results(result: Any) -> None:
    """Display scan results in a rich table."""
    from abyssforge.core.engine import ScanResult

    counts = result.severity_counts

    # Summary panel
    summary = (
        f"[bold]Scan ID:[/] {result.scan_id}\n"
        f"[bold]Target:[/] {result.target_url}\n"
        f"[bold]Duration:[/] {result.duration:.1f}s\n"
        f"[bold]URLs Scanned:[/] {len(result.urls_scanned)}\n"
        f"[bold]Total Findings:[/] {len(result.findings)}\n"
        f"[bold red]Critical:[/] {counts.get('critical', 0)} | "
        f"[bold orange3]High:[/] {counts.get('high', 0)} | "
        f"[bold yellow]Medium:[/] {counts.get('medium', 0)} | "
        f"[bold blue]Low:[/] {counts.get('low', 0)}"
    )
    console.print(Panel(summary, title="[bold cyan]Scan Complete", border_style="cyan"))

    if not result.findings:
        console.print("\n[bold green]✅ No vulnerabilities detected![/]")
        return

    # Findings table
    table = Table(
        title="\n🔍 Vulnerability Findings",
        show_lines=True,
        highlight=True,
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", width=28)
    table.add_column("Parameter", width=20)
    table.add_column("URL", width=40, overflow="fold")
    table.add_column("Confidence", width=10)

    severity_colors = {
        "critical": "bold red",
        "high": "bold orange3",
        "medium": "bold yellow",
        "low": "bold blue",
        "info": "dim",
    }

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity.lower(), 5))

    for finding in sorted_findings:
        color = severity_colors.get(finding.severity.lower(), "white")
        table.add_row(
            Text(finding.severity.upper(), style=color),
            finding.vuln_type,
            finding.parameter[:20],
            finding.url,
            finding.confidence,
        )

    console.print(table)


def _generate_reports(result: Any, output_dir: str, formats: list) -> list:
    """Generate reports in specified formats."""
    paths = []

    for fmt in formats:
        try:
            if fmt == "json":
                from abyssforge.reporters.json_reporter import JSONReporter
                reporter = JSONReporter(output_dir)
                paths.append(reporter.generate(result))
            elif fmt == "html":
                from abyssforge.reporters.html_reporter import HTMLReporter
                reporter = HTMLReporter(output_dir)
                paths.append(reporter.generate(result))
        except Exception as e:
            console.print(f"[red]Error generating {fmt} report: {e}[/]")

    return paths


@cli.command()
def modules() -> None:
    """List all available vulnerability scanning modules."""
    print_banner()

    table = Table(title="Available Modules", show_lines=True)
    table.add_column("Module", style="cyan bold")
    table.add_column("Vulnerability Type", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("CWE", style="dim")

    module_info = [
        ("sqli", "SQL Injection", "critical", "CWE-89"),
        ("xss", "Cross-Site Scripting (XSS)", "high", "CWE-79"),
        ("csrf", "Cross-Site Request Forgery", "high", "CWE-352"),
        ("lfi", "Local File Inclusion / Path Traversal", "high", "CWE-22"),
        ("cmd_injection", "OS Command Injection", "critical", "CWE-78"),
        ("misconfig", "Security Misconfiguration", "medium", "CWE-16"),
        ("api_security", "API Security Issues", "high", "CWE-285"),
    ]

    severity_colors = {
        "critical": "bold red",
        "high": "bold orange3",
        "medium": "bold yellow",
        "low": "bold blue",
    }

    for name, vuln_type, severity, cwe in module_info:
        color = severity_colors.get(severity, "white")
        table.add_row(name, vuln_type, Text(severity.upper(), style=color), cwe)

    console.print(table)


@cli.command()
@click.argument("url")
@click.option("--output", "-o", default="output", help="Output directory")
def fingerprint(url: str, output: str) -> None:
    """Fingerprint target technology stack and security headers."""
    print_banner()

    from abyssforge.utils.validators import validate_url
    url = validate_url(url)

    cfg = load_config()

    from abyssforge.core.request import RequestHandler
    rh = RequestHandler()

    console.print(f"[bold yellow]Fingerprinting:[/] {url}\n")

    try:
        response = rh.get(url)
        from abyssforge.core.parser import ResponseParser
        parser = ResponseParser(response.text, response.status_code, dict(response.headers))

        # Technologies
        techs = parser.detect_technologies()
        waf = parser.detect_waf()
        server = parser.get_server_info()
        headers = parser.check_security_headers()

        if techs:
            tech_table = Table(title="Technologies Detected")
            tech_table.add_column("Technology", style="cyan")
            for tech in techs:
                tech_table.add_row(tech)
            console.print(tech_table)

        # Security headers
        header_table = Table(title="Security Headers")
        header_table.add_column("Header", style="white")
        header_table.add_column("Status", style="bold")
        header_table.add_column("Value", style="dim")

        for header_name, info in headers.items():
            status = "[green]✓ Present[/]" if info["present"] else "[red]✗ Missing[/]"
            header_table.add_row(header_name, status, info.get("value") or "")

        console.print(header_table)

        if waf:
            console.print(f"\n[yellow]WAF Detected:[/] {waf}")

        for k, v in server.items():
            if v:
                console.print(f"[dim]{k}:[/] {v}")

        rh.close()

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        rh.close()
        sys.exit(1)


# Type hint fix
from typing import Any
