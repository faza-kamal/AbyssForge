"""
AbyssForge - Web Dashboard (Flask)
Dashboard read-only untuk memantau hasil scan.
Tidak boleh import core atau modules langsung.
Tidak melakukan scanning — hanya menampilkan data dari database.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def create_app():
    """Factory function untuk Flask app."""
    try:
        from flask import Flask, render_template, jsonify, request, abort
    except ImportError:
        raise RuntimeError(
            "Flask tidak terinstall. Jalankan: pip install flask"
        )

    from database.db import Database
    from reporting.reporter import Reporter

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    db = Database()

    # ─── Routes ───────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        scans = db.get_all_scans()
        return render_template("index.html", scans=scans)

    @app.route("/scan/<int:scan_id>")
    def scan_detail(scan_id: int):
        scan = db.get_scan(scan_id)
        if not scan:
            abort(404)
        findings = db.get_findings(scan_id)
        stats    = db.get_finding_stats(scan_id)
        return render_template(
            "scan_detail.html",
            scan=scan,
            findings=findings,
            stats=stats,
        )

    @app.route("/api/scans")
    def api_scans():
        return jsonify(db.get_all_scans())

    @app.route("/api/scans/<int:scan_id>")
    def api_scan(scan_id: int):
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        findings = db.get_findings(
            scan_id,
            severity=request.args.get("severity"),
            vuln_type=request.args.get("type"),
        )
        stats = db.get_finding_stats(scan_id)
        return jsonify({"scan": scan, "findings": findings, "stats": stats})

    @app.route("/api/search")
    def api_search():
        kw = request.args.get("q", "").strip()
        if not kw:
            return jsonify([])
        return jsonify(db.search_findings(kw))

    @app.route("/report/<int:scan_id>/<fmt>")
    def download_report(scan_id: int, fmt: str):
        if fmt not in ("json", "html"):
            abort(400)

        import tempfile
        from flask import send_file

        scan = db.get_scan(scan_id)
        if not scan:
            abort(404)

        reporter = Reporter(db)
        with tempfile.NamedTemporaryFile(
            suffix=f".{fmt}", delete=False, prefix=f"abyss_report_{scan_id}_"
        ) as tmp:
            path = reporter.generate(scan_id, fmt, tmp.name)

        return send_file(
            path,
            as_attachment=True,
            download_name=f"abyssforge_report_{scan_id}.{fmt}",
        )

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", error="Halaman tidak ditemukan."), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", error="Internal Server Error."), 500

    return app
