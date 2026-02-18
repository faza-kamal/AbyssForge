"""
AbyssForge Logging System
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for rich console
CUSTOM_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "vuln": "bold magenta",
    "highlight": "bold yellow",
})

console = Console(theme=CUSTOM_THEME)


def setup_logger(
    name: str = "abyssforge",
    level: str = "INFO",
    log_file: Optional[str] = None,
    rich_output: bool = True,
) -> logging.Logger:
    """
    Setup and configure logger for AbyssForge.

    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path for log output
        rich_output: Whether to use Rich for formatted output

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    logger.handlers.clear()

    if rich_output:
        handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

    logger.addHandler(handler)

    if log_file:
        file_handler = logging.FileHandler(Path(log_file), encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "abyssforge") -> logging.Logger:
    """Get existing logger by name."""
    return logging.getLogger(name)


class VulnLogger:
    """Special logger for vulnerability findings."""

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def found(self, vuln_type: str, url: str, parameter: str, severity: str) -> None:
        """Log a found vulnerability."""
        severity_colors = {
            "critical": "[bold white on red]",
            "high": "[bold red]",
            "medium": "[bold yellow]",
            "low": "[bold blue]",
            "info": "[bold cyan]",
        }
        color = severity_colors.get(severity.lower(), "[bold white]")
        self.logger.warning(
            f"{color}[{severity.upper()}][/] {vuln_type} found at {url} | Parameter: {parameter}"
        )

    def info(self, message: str) -> None:
        """Log informational message."""
        self.logger.info(f"[info]{message}[/]")

    def success(self, message: str) -> None:
        """Log success message."""
        self.logger.info(f"[success]{message}[/]")

    def error(self, message: str) -> None:
        """Log error message."""
        self.logger.error(f"[error]{message}[/]")
