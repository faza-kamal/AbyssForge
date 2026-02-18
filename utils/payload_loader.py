"""
AbyssForge - Payload & Wordlist Loader
Memuat payload dari folder data/payloads dan data/wordlists.
Tidak boleh import modules, database, dashboard, atau reporting.
"""

import logging
import os
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Root direktori AbyssForge
BASE_DIR = Path(__file__).parent.parent
PAYLOADS_DIR = BASE_DIR / "data" / "payloads"
WORDLISTS_DIR = BASE_DIR / "data" / "wordlists"


def load_payloads(name: str) -> List[str]:
    """
    Muat payload dari file di data/payloads/{name}.txt.
    Mengembalikan list string, kosong jika file tidak ditemukan.
    """
    path = PAYLOADS_DIR / f"{name}.txt"
    return _read_lines(path, label=f"payload:{name}")


def load_wordlist(name: str) -> List[str]:
    """
    Muat wordlist dari file di data/wordlists/{name}.txt.
    """
    path = WORDLISTS_DIR / f"{name}.txt"
    return _read_lines(path, label=f"wordlist:{name}")


def _read_lines(path: Path, label: str) -> List[str]:
    """Baca file baris per baris, skip komentar (#) dan baris kosong."""
    if not path.exists():
        logger.debug("File tidak ditemukan: %s", path)
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        result = [
            line.strip()
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        ]
        logger.debug("Dimuat %d entri dari %s", len(result), label)
        return result
    except Exception as exc:
        logger.error("Gagal membaca %s: %s", path, exc)
        return []


def list_available() -> dict:
    """Kembalikan dict berisi semua file payload dan wordlist yang tersedia."""
    return {
        "payloads": sorted(
            p.stem for p in PAYLOADS_DIR.glob("*.txt") if p.is_file()
        ),
        "wordlists": sorted(
            w.stem for w in WORDLISTS_DIR.glob("*.txt") if w.is_file()
        ),
    }
