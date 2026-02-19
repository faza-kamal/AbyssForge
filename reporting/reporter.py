"""
AbyssForge - Reporter
Generate laporan dalam format JSON, HTML, dan PDF.
Tidak boleh import dashboard.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

SEVERITY_BADGES = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


class Reporter:
    """
    Menghasilkan laporan dari data scan yang tersimpan di database.
    Database diinjeksikan dari luar untuk menjaga layering.
    """

    def __init__(self, db: Any):
        self.db = db

    def _collect_data(self, scan_id: int) -> Dict:
        scan = self.db.get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan ID {scan_id} tidak ditemukan di database.")

        findings = self.db.get_findings(scan_id)
        stats = self.db.get_finding_stats(scan_id)

        return {
            "scan": scan,
            "findings": findings,
            "stats": stats,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total": len(findings),
        }

    def generate(self, scan_id: int, fmt: str, output_path: str) -> str:
        """
        Generate laporan.

        Args:
            scan_id:     ID scan yang akan di-report.
            fmt:         'json', 'html', atau 'pdf'.
            output_path: Path file output.

        Returns:
            Path file yang dihasilkan.
        """
        data = self._collect_data(scan_id)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "json":
            return self._generate_json(data, out)
        elif fmt == "html":
            return self._generate_html(data, out)
        elif fmt == "pdf":
            return self._generate_pdf(data, out)
        else:
            raise ValueError(f"Format tidak dikenal: {fmt}")

    # ─── JSON ─────────────────────────────────────────────────────────────────

    def _generate_json(self, data: Dict, out: Path) -> str:
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("JSON report dibuat: %s", out)
        return str(out)

    # ─── HTML ─────────────────────────────────────────────────────────────────

    def _generate_html(self, data: Dict, out: Path) -> str:
        html = self._build_html(data)
        out.write_text(html, encoding="utf-8")
        logger.info("HTML report dibuat: %s", out)
        return str(out)

    def _build_html(self, data: Dict) -> str:
        scan     = data["scan"]
        findings = data["findings"]
        stats    = data["stats"]
        generated = data["generated_at"]

        # Severity summary bars
        sev_bars = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = stats.get(sev, 0)
            if count:
                color = SEVERITY_COLORS[sev]
                badge = SEVERITY_BADGES[sev]
                sev_bars += f"""
                <div class="stat-card" style="border-left: 4px solid {color};">
                    <span class="sev-badge">{badge} {sev}</span>
                    <span class="sev-count">{count}</span>
                </div>"""

        # Finding rows
        finding_rows = ""
        for f in findings:
            sev = f["severity"]
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            badge = SEVERITY_BADGES.get(sev, "⚪")
            finding_rows += f"""
            <div class="finding-card" id="finding-{f['id']}">
                <div class="finding-header" onclick="toggleFinding(this)">
                    <span class="sev-pill" style="background:{color}">
                        {badge} {sev}
                    </span>
                    <span class="finding-title">{self._esc(f['title'])}</span>
                    <span class="cvss-badge">CVSS {f['cvss_score']:.1f}</span>
                    <span class="toggle-icon">▼</span>
                </div>
                <div class="finding-body">
                    <table class="detail-table">
                        <tr><th>URL</th><td><code>{self._esc(f['url'])}</code></td></tr>
                        {"<tr><th>Parameter</th><td><code>" + self._esc(f['parameter']) + "</code></td></tr>" if f.get('parameter') else ""}
                        <tr><th>Method</th><td>{self._esc(f['method'])}</td></tr>
                        <tr><th>Modul</th><td>{self._esc(f['module'])}</td></tr>
                        <tr><th>Confidence</th><td>{self._esc(f['confidence'])}</td></tr>
                    </table>
                    <div class="section-label">Deskripsi</div>
                    <p>{self._esc(f['description'])}</p>
                    {"<div class='section-label'>Evidence</div><pre class='code-block'>" + self._esc(f['evidence'][:800]) + "</pre>" if f.get('evidence') else ""}
                    {"<div class='section-label'>Payload</div><pre class='code-block'>" + self._esc(f['payload'][:400]) + "</pre>" if f.get('payload') else ""}
                    <div class="section-label">Remediasi</div>
                    <p class="remediation">{self._esc(f['remediation'])}</p>
                    {"<div class='section-label'>Referensi</div><p><a href='" + f.get('refs','') + "' target='_blank'>" + self._esc((f.get('refs',''))[:80]) + "</a></p>" if f.get('refs') else ""}
                </div>
            </div>"""

        if not finding_rows:
            finding_rows = '<div class="no-findings">✅ Tidak ada kerentanan yang ditemukan.</div>'

        # Config display
        try:
            cfg = json.loads(scan.get("config", "{}"))
        except Exception:
            cfg = {}

        return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AbyssForge Report — {self._esc(scan['target'])}</title>
<style>
:root {{
  --bg: #0f172a; --card: #1e293b; --border: #334155;
  --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
  --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: var(--font);
       font-size: 14px; line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 24px 16px; }}
header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
          border-bottom: 1px solid var(--border); padding: 32px 16px;
          text-align: center; }}
header h1 {{ font-size: 2rem; color: var(--accent); letter-spacing: 2px; }}
header h1 span {{ color: #7dd3fc; }}
.meta {{ color: var(--muted); font-size: 13px; margin-top: 8px; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                 gap: 12px; margin: 24px 0; }}
.stat-card {{ background: var(--card); border-radius: 8px; padding: 16px 20px;
              display: flex; justify-content: space-between; align-items: center; }}
.sev-badge {{ font-weight: 600; font-size: 13px; }}
.sev-count {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
.section-title {{ font-size: 1.1rem; font-weight: 700; color: var(--accent);
                  margin: 24px 0 12px; border-bottom: 1px solid var(--border);
                  padding-bottom: 8px; }}
.finding-card {{ background: var(--card); border-radius: 8px; margin-bottom: 10px;
                 border: 1px solid var(--border); overflow: hidden; }}
.finding-header {{ padding: 14px 16px; cursor: pointer; display: flex;
                   align-items: center; gap: 12px; user-select: none; }}
.finding-header:hover {{ background: #263548; }}
.sev-pill {{ padding: 3px 10px; border-radius: 20px; font-size: 11px;
             font-weight: 700; color: #fff; white-space: nowrap; }}
.finding-title {{ flex: 1; font-weight: 600; }}
.cvss-badge {{ background: #1e3a5f; padding: 2px 8px; border-radius: 4px;
               font-size: 11px; color: var(--accent); }}
.toggle-icon {{ color: var(--muted); transition: transform 0.2s; }}
.finding-header.open .toggle-icon {{ transform: rotate(180deg); }}
.finding-body {{ display: none; padding: 16px; border-top: 1px solid var(--border); }}
.finding-body.open {{ display: block; }}
.detail-table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; }}
.detail-table th {{ width: 120px; text-align: left; color: var(--muted); padding: 6px 12px 6px 0; }}
.detail-table td {{ padding: 6px 0; }}
.detail-table code {{ background: #0f172a; padding: 2px 8px; border-radius: 4px;
                      font-size: 12px; word-break: break-all; }}
.section-label {{ font-size: 12px; font-weight: 700; color: var(--accent);
                  text-transform: uppercase; letter-spacing: 1px; margin: 12px 0 6px; }}
.code-block {{ background: #0f172a; border: 1px solid var(--border); border-radius: 6px;
               padding: 10px 12px; font-size: 12px; overflow-x: auto;
               white-space: pre-wrap; word-break: break-all; color: #86efac; }}
.remediation {{ background: #0c2e0c; border-left: 3px solid #22c55e;
                padding: 10px 14px; border-radius: 0 6px 6px 0; }}
.no-findings {{ text-align: center; padding: 40px; color: #22c55e; font-size: 1.1rem; }}
.info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
              background: var(--card); border-radius: 8px; padding: 16px; margin: 16px 0; }}
.info-item label {{ color: var(--muted); font-size: 12px; display: block; }}
.info-item span {{ font-weight: 600; }}
footer {{ text-align: center; color: var(--muted); font-size: 12px;
          padding: 24px; border-top: 1px solid var(--border); margin-top: 40px; }}
</style>
</head>
<body>
<header>
  <h1>ABYSS<span>FORGE</span></h1>
  <div class="meta">Web Vulnerability Scanner Report &bull; by faza-kamal</div>
</header>
<div class="container">
  <div class="section-title">Informasi Scan</div>
  <div class="info-grid">
    <div class="info-item"><label>Target</label><span>{self._esc(scan['target'])}</span></div>
    <div class="info-item"><label>Scan ID</label><span>#{scan['id']}</span></div>
    <div class="info-item"><label>Modul</label><span>{self._esc(scan['modules'])}</span></div>
    <div class="info-item"><label>Status</label><span>{self._esc(scan['status'])}</span></div>
    <div class="info-item"><label>Dimulai</label><span>{self._esc(scan['created_at'])}</span></div>
    <div class="info-item"><label>Selesai</label><span>{self._esc(str(scan.get('finished_at', '-')))}</span></div>
    <div class="info-item"><label>Total Temuan</label><span>{scan['total_findings']}</span></div>
    <div class="info-item"><label>Dibuat</label><span>{generated}</span></div>
  </div>

  <div class="section-title">Ringkasan Severity</div>
  <div class="summary-grid">
    {sev_bars or '<div class="no-findings">Tidak ada temuan.</div>'}
  </div>

  <div class="section-title">Detail Temuan</div>
  {finding_rows}
</div>
<footer>
  AbyssForge v1.0.0 &bull; <a href="https://github.com/faza-kamal/AbyssForge" style="color:var(--accent)">github.com/faza-kamal/AbyssForge</a>
  &bull; Hanya untuk pengujian keamanan yang sah.
</footer>
<script>
function toggleFinding(header) {{
  header.classList.toggle('open');
  const body = header.nextElementSibling;
  body.classList.toggle('open');
}}
// Auto-buka temuan CRITICAL/HIGH
document.querySelectorAll('.finding-header').forEach(h => {{
  if (h.querySelector('.sev-pill').textContent.includes('CRITICAL') ||
      h.querySelector('.sev-pill').textContent.includes('HIGH')) {{
    h.click();
  }}
}});
</script>
</body>
</html>"""

    def _esc(self, text: str) -> str:
        """HTML escape."""
        if not isinstance(text, str):
            text = str(text)
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    # ─── PDF ──────────────────────────────────────────────────────────────────

    def _generate_pdf(self, data: Dict, out: Path) -> str:
        """
        Generate PDF menggunakan WeasyPrint (opsional).
        Jika tidak tersedia, simpan sebagai HTML dan beri tahu user.
        """
        try:
            from weasyprint import HTML as WeasyHTML
            html_content = self._build_html(data)
            WeasyHTML(string=html_content).write_pdf(str(out))
            logger.info("PDF report dibuat: %s", out)
            return str(out)
        except ImportError:
            # Fallback ke HTML jika WeasyPrint tidak tersedia
            fallback = out.with_suffix(".html")
            logger.warning(
                "WeasyPrint tidak terinstall. Menyimpan sebagai HTML: %s", fallback
            )
            return self._generate_html(data, fallback)
        except Exception as exc:
            logger.error("Gagal membuat PDF: %s", exc)
            raise
