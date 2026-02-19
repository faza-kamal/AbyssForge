#!/usr/bin/env python3
"""
AbyssForge - Web Vulnerability Scanner
Author: faza-kamal (https://github.com/faza-kamal/AbyssForge)
Version: 1.0.0
"""

import argparse
import asyncio
import sys
import logging
from pathlib import Path

# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
 █████╗ ██████╗ ██╗   ██╗███████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
███████║██████╔╝ ╚████╔╝ ███████╗███████╗█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
██╔══██║██╔══██╗  ╚██╔╝  ╚════██║╚════██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
██║  ██║██████╔╝   ██║   ███████║███████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝╚═════╝    ╚═╝   ╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

  Web Vulnerability Scanner | v1.0.0 | by faza-kamal
  https://github.com/faza-kamal/AbyssForge
  [!] Hanya untuk pengujian keamanan yang sah / Authorized security testing only
"""

# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abyssforge",
        description="AbyssForge - Professional Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh Penggunaan:
  python3 main.py --scan https://target.com
  python3 main.py --scan https://target.com --full
  python3 main.py --scan https://target.com --module sqli,xss
  python3 main.py --report 1 --format html
  python3 main.py --dashboard
        """
    )

    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--scan", metavar="URL", help="Target URL untuk di-scan")
    scan_group.add_argument("--full", action="store_true", help="Jalankan semua modul deteksi")
    scan_group.add_argument(
        "--module", metavar="MODULES",
        help="Modul spesifik (pisahkan koma): sqli,xss,ssrf,xxe,ssti,csrf,auth,misconfig,exposure,redirect"
    )
    scan_group.add_argument("--threads", type=int, default=10, help="Jumlah thread (default: 10)")
    scan_group.add_argument("--timeout", type=int, default=10, help="Request timeout dalam detik (default: 10)")
    scan_group.add_argument("--depth", type=int, default=2, help="Kedalaman crawl (default: 2)")
    scan_group.add_argument("--delay", type=float, default=0.5, help="Delay antar request dalam detik (default: 0.5)")
    scan_group.add_argument("--user-agent", metavar="UA", help="Custom User-Agent string")
    scan_group.add_argument("--cookie", metavar="COOKIE", help="Cookie untuk authenticated scan")
    scan_group.add_argument("--header", metavar="HEADER", action="append", help="Header tambahan (format: Key:Value)")

    report_group = parser.add_argument_group("Report Options")
    report_group.add_argument("--report", type=int, metavar="SCAN_ID", help="Generate laporan dari scan ID")
    report_group.add_argument("--format", choices=["json", "html", "pdf"], default="html", help="Format laporan (default: html)")
    report_group.add_argument("--output", metavar="PATH", help="Path output laporan")

    other_group = parser.add_argument_group("Other Options")
    other_group.add_argument("--dashboard", action="store_true", help="Jalankan web dashboard")
    other_group.add_argument("--port", type=int, default=5000, help="Port dashboard (default: 5000)")
    other_group.add_argument("--list-scans", action="store_true", help="Tampilkan semua scan yang tersimpan")
    other_group.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    other_group.add_argument("--debug", action="store_true", help="Debug mode")

    return parser


# ─── Main Orchestrator ────────────────────────────────────────────────────────

async def run_scan(args: argparse.Namespace) -> None:
    from core.engine import ScanEngine
    from core.config import ScanConfig
    from database.db import Database
    from reporting.reporter import Reporter

    # Bangun konfigurasi
    modules = []
    if args.full:
        modules = ["sqli", "xss", "ssrf", "xxe", "ssti", "csrf", "auth", "misconfig", "exposure", "redirect"]
    elif args.module:
        modules = [m.strip().lower() for m in args.module.split(",")]
    else:
        # Default: modul dasar
        modules = ["sqli", "xss", "misconfig", "exposure"]

    extra_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    config = ScanConfig(
        target_url=args.scan,
        modules=modules,
        max_threads=args.threads,
        timeout=args.timeout,
        crawl_depth=args.depth,
        delay=args.delay,
        user_agent=args.user_agent,
        cookie=args.cookie,
        extra_headers=extra_headers,
        verbose=args.verbose,
    )

    db = Database()
    engine = ScanEngine(config, db)

    print(f"\n[*] Target  : {args.scan}")
    print(f"[*] Modules : {', '.join(modules)}")
    print(f"[*] Depth   : {args.depth}")
    print(f"[*] Threads : {args.threads}")
    print("-" * 60)

    scan_id = await engine.run()

    print(f"\n[+] Scan selesai! Scan ID: {scan_id}")
    print(f"[*] Generate laporan: python3 main.py --report {scan_id} --format html")


def run_report(args: argparse.Namespace) -> None:
    from database.db import Database
    from reporting.reporter import Reporter

    db = Database()
    reporter = Reporter(db)

    output_path = args.output or f"report_{args.report}.{args.format}"
    reporter.generate(scan_id=args.report, fmt=args.format, output_path=output_path)
    print(f"[+] Laporan berhasil dibuat: {output_path}")


def run_dashboard(args: argparse.Namespace) -> None:
    from dashboard.app import create_app

    app = create_app()
    print(f"[*] Dashboard berjalan di http://127.0.0.1:{args.port}")
    app.run(host="0.0.0.0", port=args.port, debug=args.debug)


def list_scans() -> None:
    from database.db import Database

    db = Database()
    scans = db.get_all_scans()
    if not scans:
        print("[-] Belum ada scan yang tersimpan.")
        return

    print(f"\n{'ID':<6} {'Target':<40} {'Modules':<30} {'Findings':<10} {'Date'}")
    print("-" * 100)
    for s in scans:
        print(f"{s['id']:<6} {s['target'][:38]:<40} {s['modules'][:28]:<30} {s['total_findings']:<10} {s['created_at']}")


# ─── Entry ────────────────────────────────────────────────────────────────────

def main() -> None:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    # Setup logging
    level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=level,
    )

    if args.scan:
        asyncio.run(run_scan(args))
    elif args.report:
        run_report(args)
    elif args.dashboard:
        run_dashboard(args)
    elif args.list_scans:
        list_scans()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
