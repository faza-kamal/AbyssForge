"""
AbyssForge JSON Reporter
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from abyssforge.core.engine import ScanResult
from abyssforge.core.exceptions import ReportError
from abyssforge.utils.logger import get_logger

logger = get_logger("abyssforge.reporter.json")


class JSONReporter:
    """Generates JSON format reports from scan results."""

    def __init__(self, output_dir: str = "output") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """
        Generate JSON report.

        Args:
            result: ScanResult to report on
            filename: Optional custom filename

        Returns:
            Path to generated report file
        """
        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"abyssforge_{result.scan_id}_{timestamp}.json"

        filepath = self.output_dir / filename

        try:
            report_data = {
                "meta": {
                    "tool": "AbyssForge",
                    "version": "1.0.0",
                    "author": "faza-kamal",
                    "github": "https://github.com/faza-kamal/AbyssForge",
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "disclaimer": (
                        "This tool is intended for authorized security testing only. "
                        "Unauthorized use is illegal and unethical."
                    ),
                },
                "scan": result.to_dict(),
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

            logger.info(f"JSON report saved: {filepath}")
            return str(filepath)

        except Exception as e:
            raise ReportError(f"Failed to generate JSON report: {e}")


# Fix missing Optional import
from typing import Optional
