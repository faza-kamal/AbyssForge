"""
AbyssForge HTML Reporter
Generates professional HTML security reports.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from abyssforge.core.engine import ScanResult
from abyssforge.core.exceptions import ReportError
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.reporter.html")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AbyssForge Security Report - {target}</title>
    <style>
        :root {{
            --critical: #dc3545; --high: #fd7e14; --medium: #ffc107;
            --low: #17a2b8; --info: #6c757d; --bg: #0d1117; --card: #161b22;
            --border: #30363d; --text: #c9d1d9; --text-muted: #8b949e;
            --accent: #58a6ff; --success: #3fb950;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                   padding: 40px; text-align: center; border-bottom: 2px solid var(--accent); }}
        .header h1 {{ font-size: 2.5rem; color: var(--accent); font-weight: 700; }}
        .header h1 span {{ color: #f0f6fc; }}
        .header .subtitle {{ color: var(--text-muted); margin-top: 8px; font-size: 1rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 20px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                       gap: 16px; margin-bottom: 30px; }}
        .stat-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
                      padding: 20px; text-align: center; }}
        .stat-card .number {{ font-size: 2.5rem; font-weight: 700; }}
        .stat-card .label {{ font-size: 0.85rem; color: var(--text-muted); margin-top: 4px; }}
        .critical .number {{ color: var(--critical); }}
        .high .number {{ color: var(--high); }}
        .medium .number {{ color: var(--medium); }}
        .low .number {{ color: var(--low); }}
        .info-card {{ color: var(--info); }}
        .section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
                    margin-bottom: 24px; overflow: hidden; }}
        .section-header {{ padding: 16px 20px; border-bottom: 1px solid var(--border);
                           font-weight: 600; font-size: 1.1rem; }}
        .section-body {{ padding: 20px; }}
        .finding {{ border-left: 4px solid var(--border); padding: 16px; margin-bottom: 16px;
                    background: rgba(255,255,255,0.02); border-radius: 0 6px 6px 0; }}
        .finding.critical {{ border-left-color: var(--critical); }}
        .finding.high {{ border-left-color: var(--high); }}
        .finding.medium {{ border-left-color: var(--medium); }}
        .finding.low {{ border-left-color: var(--low); }}
        .finding.info {{ border-left-color: var(--info); }}
        .finding-title {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .finding-title h3 {{ font-size: 1rem; color: #f0f6fc; }}
        .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600;
                  text-transform: uppercase; }}
        .badge.critical {{ background: rgba(220,53,69,0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge.high {{ background: rgba(253,126,20,0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge.medium {{ background: rgba(255,193,7,0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge.low {{ background: rgba(23,162,184,0.2); color: var(--low); border: 1px solid var(--low); }}
        .badge.info {{ background: rgba(108,117,125,0.2); color: var(--info); border: 1px solid var(--info); }}
        .finding-detail {{ font-size: 0.875rem; color: var(--text-muted); margin: 4px 0; }}
        .finding-detail strong {{ color: var(--text); }}
        .code {{ background: #0d1117; border: 1px solid var(--border); border-radius: 4px;
                 padding: 8px 12px; font-family: monospace; font-size: 0.8rem; color: #7ee787;
                 word-break: break-all; margin-top: 8px; }}
        .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
        .meta-item {{ display: flex; gap: 8px; }}
        .meta-item .key {{ color: var(--text-muted); min-width: 140px; font-size: 0.875rem; }}
        .meta-item .val {{ color: var(--text); font-size: 0.875rem; word-break: break-all; }}
        .no-findings {{ text-align: center; padding: 40px; color: var(--success);
                        font-size: 1.1rem; }}
        .tech-tag {{ display: inline-block; background: rgba(88,166,255,0.1); color: var(--accent);
                     border: 1px solid var(--accent); border-radius: 12px; padding: 2px 10px;
                     font-size: 0.8rem; margin: 4px 4px 4px 0; }}
        .footer {{ text-align: center; padding: 30px; color: var(--text-muted); font-size: 0.8rem;
                   border-top: 1px solid var(--border); margin-top: 30px; }}
        .disclaimer {{ background: rgba(220,53,69,0.1); border: 1px solid var(--critical);
                       border-radius: 6px; padding: 12px 16px; margin-bottom: 24px; font-size: 0.875rem; }}
    </style>
</head>
<body>
<div class="header">
    <h1>⚡ Abyss<span>Forge</span></h1>
    <div class="subtitle">Web Vulnerability Scanner | Security Report</div>
    <div class="subtitle" style="margin-top: 4px; color: #58a6ff;">
        Target: {target} | Scan ID: {scan_id}
    </div>
</div>

<div class="container">
    <div class="disclaimer">
        ⚠️ <strong>Legal Disclaimer:</strong> This report is intended for authorized security testing only.
        Unauthorized testing is illegal. Always obtain written permission before testing.
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="number" style="color: var(--accent)">{total}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="stat-card critical">
            <div class="number">{critical}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
            <div class="number">{high}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card medium">
            <div class="number">{medium}</div>
            <div class="label">Medium</div>
        </div>
        <div class="stat-card low">
            <div class="number">{low}</div>
            <div class="label">Low</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: var(--success)">{urls_scanned}</div>
            <div class="label">URLs Scanned</div>
        </div>
    </div>

    <div class="section">
        <div class="section-header">📋 Scan Information</div>
        <div class="section-body">
            <div class="meta-grid">
                <div class="meta-item"><span class="key">Target URL:</span><span class="val">{target}</span></div>
                <div class="meta-item"><span class="key">Scan ID:</span><span class="val">{scan_id}</span></div>
                <div class="meta-item"><span class="key">Start Time:</span><span class="val">{start_time}</span></div>
                <div class="meta-item"><span class="key">Duration:</span><span class="val">{duration}</span></div>
                <div class="meta-item"><span class="key">WAF Detected:</span><span class="val">{waf}</span></div>
                <div class="meta-item"><span class="key">Technologies:</span><span class="val">{techs}</span></div>
            </div>
        </div>
    </div>

    <div class="section">
        <div class="section-header">🔍 Vulnerability Findings</div>
        <div class="section-body">
            {findings_html}
        </div>
    </div>
</div>

<div class="footer">
    Generated by <strong>AbyssForge v1.0.0</strong> | 
    <a href="https://github.com/faza-kamal/AbyssForge" style="color: var(--accent);">GitHub</a> |
    {generated_at}
</div>
</body>
</html>"""

FINDING_TEMPLATE = """
<div class="finding {severity}">
    <div class="finding-title">
        <h3>{vuln_type}</h3>
        <span class="badge {severity}">{severity}</span>
    </div>
    <div class="finding-detail"><strong>URL:</strong> {url}</div>
    <div class="finding-detail"><strong>Parameter:</strong> {parameter}</div>
    <div class="finding-detail"><strong>Confidence:</strong> {confidence}</div>
    <div class="finding-detail"><strong>CWE:</strong> {cwe}</div>
    <div class="finding-detail"><strong>Evidence:</strong> {evidence}</div>
    <div class="finding-detail"><strong>Description:</strong> {description}</div>
    <div class="finding-detail"><strong>Remediation:</strong> {remediation}</div>
    <div class="code">Payload: {payload}</div>
</div>
"""


class HTMLReporter:
    """Generates HTML security reports."""

    def __init__(self, output_dir: str = "output") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """Generate HTML report."""
        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"abyssforge_{result.scan_id}_{timestamp}.html"

        filepath = self.output_dir / filename

        try:
            # Build findings HTML
            if result.findings:
                # Sort by severity
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                sorted_findings = sorted(
                    result.findings,
                    key=lambda f: severity_order.get(f.severity.lower(), 5)
                )

                findings_html = "".join(
                    FINDING_TEMPLATE.format(
                        vuln_type=self._escape(f.vuln_type),
                        severity=f.severity.lower(),
                        url=self._escape(f.url),
                        parameter=self._escape(f.parameter),
                        confidence=self._escape(f.confidence),
                        cwe=self._escape(f.cwe or "N/A"),
                        evidence=self._escape(f.evidence),
                        description=self._escape(f.description),
                        remediation=self._escape(f.remediation),
                        payload=self._escape(f.payload[:200]),
                    )
                    for f in sorted_findings
                )
            else:
                findings_html = '<div class="no-findings">✅ No vulnerabilities detected!</div>'

            # Build tech tags
            techs_html = (
                "".join(f'<span class="tech-tag">{t}</span>' for t in result.technologies)
                if result.technologies else "Not detected"
            )

            counts = result.severity_counts
            html = HTML_TEMPLATE.format(
                target=self._escape(result.target_url),
                scan_id=self._escape(result.scan_id),
                total=len(result.findings),
                critical=counts.get("critical", 0),
                high=counts.get("high", 0),
                medium=counts.get("medium", 0),
                low=counts.get("low", 0),
                urls_scanned=len(result.urls_scanned),
                start_time=datetime.fromtimestamp(result.start_time).strftime("%Y-%m-%d %H:%M:%S UTC"),
                duration=f"{result.duration:.1f}s",
                waf=self._escape(result.waf_detected or "Not detected"),
                techs=techs_html,
                findings_html=findings_html,
                generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            )

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)

            logger.info(f"HTML report saved: {filepath}")
            return str(filepath)

        except Exception as e:
            raise ReportError(f"Failed to generate HTML report: {e}")

    def _escape(self, text: str) -> str:
        """HTML-escape a string."""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
