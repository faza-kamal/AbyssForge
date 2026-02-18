"""
AbyssForge - Logger Utility
Setup logging terpusat dengan format dan handler yang konsisten.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime


def setup_logger(
    name: str = "abyssforge",
    level: int = logging.INFO,
    log_file: bool = True,
    log_dir: str = "logs",
) -> logging.Logger:
    """
    Buat dan konfigurasi logger utama AbyssForge.

    Args:
        name:     Nama logger.
        level:    Level logging (default INFO).
        log_file: Apakah log juga ditulis ke file.
        log_dir:  Direktori untuk file log.

    Returns:
        Logger yang sudah dikonfigurasi.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger  # Sudah dikonfigurasi

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    ch.setLevel(level)
    logger.addHandler(ch)

    # File handler
    if log_file:
        log_path = Path(log_dir)
        log_path.mkdir(exist_ok=True)
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fh = logging.FileHandler(log_path / f"abyssforge_{stamp}.log", encoding="utf-8")
        fh.setFormatter(formatter)
        fh.setLevel(logging.DEBUG)  # File selalu DEBUG untuk forensics
        logger.addHandler(fh)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Ambil logger anak dari namespace AbyssForge."""
    return logging.getLogger(f"abyssforge.{name}")
