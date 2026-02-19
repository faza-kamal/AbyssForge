"""
AbyssForge - Unit Tests
Jalankan dengan: pytest tests/ -v
"""

import asyncio
import sys
from pathlib import Path

# Tambah root ke sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import tempfile


# ─── Test: Core Config ────────────────────────────────────────────────────────

def test_scan_config_defaults():
    from core.config import ScanConfig
    cfg = ScanConfig(target_url="https://example.com")
    assert cfg.target_url == "https://example.com"
    assert cfg.max_threads == 10
    assert cfg.crawl_depth == 2
    assert "sqli" in cfg.modules


def test_cvss_to_severity():
    from core.config import cvss_to_severity
    assert cvss_to_severity(9.5) == "CRITICAL"
    assert cvss_to_severity(8.0) == "HIGH"
    assert cvss_to_severity(5.0) == "MEDIUM"
    assert cvss_to_severity(2.0) == "LOW"
    assert cvss_to_severity(0.0) == "INFO"


def test_scan_config_to_dict():
    from core.config import ScanConfig
    cfg = ScanConfig(target_url="https://example.com", modules=["sqli", "xss"])
    d = cfg.to_dict()
    assert d["target_url"] == "https://example.com"
    assert "sqli" in d["modules"]


# ─── Test: Finding Model ──────────────────────────────────────────────────────

def test_finding_from_cvss():
    from core.finding import Finding
    f = Finding.from_cvss(
        cvss_score=9.8,
        title="Test Finding",
        vuln_type="sqli",
        url="https://example.com/?id=1",
    )
    assert f.severity == "CRITICAL"
    assert f.cvss_score == 9.8
    assert f.title == "Test Finding"


def test_finding_to_dict():
    from core.finding import Finding
    f = Finding.from_cvss(
        cvss_score=7.5,
        title="XSS Test",
        vuln_type="xss",
        url="https://example.com",
        parameter="q",
    )
    d = f.to_dict()
    assert d["title"] == "XSS Test"
    assert d["severity"] == "HIGH"
    assert d["parameter"] == "q"
    assert "timestamp" in d


def test_finding_str():
    from core.finding import Finding
    f = Finding.from_cvss(
        cvss_score=5.0,
        title="Header Missing",
        vuln_type="misconfig",
        url="https://example.com",
    )
    s = str(f)
    assert "MEDIUM" in s
    assert "Header Missing" in s


# ─── Test: URL Utils ─────────────────────────────────────────────────────────

def test_url_validation():
    from utils.url_utils import is_valid_url
    assert is_valid_url("https://example.com") is True
    assert is_valid_url("http://example.com/path?q=1") is True
    assert is_valid_url("ftp://example.com") is False
    assert is_valid_url("not-a-url") is False
    assert is_valid_url("") is False


def test_normalize_url():
    from utils.url_utils import normalize_url
    assert normalize_url("example.com") == "https://example.com/"
    assert normalize_url("https://example.com/") == "https://example.com/"
    assert normalize_url("http://example.com") == "http://example.com/"


def test_inject_param():
    from utils.url_utils import inject_param
    result = inject_param("https://example.com/?id=1", "id", "' OR 1=1--")
    assert "id=" in result
    assert "example.com" in result


def test_extract_domain():
    from utils.url_utils import extract_domain
    assert extract_domain("https://example.com/path") == "example.com"
    assert extract_domain("https://sub.example.com:8080/") == "sub.example.com:8080"


def test_get_params():
    from utils.url_utils import get_params
    params = get_params("https://example.com/?id=1&name=test")
    assert params["id"] == "1"
    assert params["name"] == "test"


# ─── Test: Payload Loader ─────────────────────────────────────────────────────

def test_load_payloads_xss():
    from utils.payload_loader import load_payloads
    payloads = load_payloads("xss")
    assert isinstance(payloads, list)
    assert len(payloads) > 0
    # Tidak boleh ada komentar atau baris kosong
    assert all(p.strip() and not p.startswith("#") for p in payloads)


def test_load_payloads_sqli():
    from utils.payload_loader import load_payloads
    payloads = load_payloads("sqli_error")
    assert isinstance(payloads, list)
    assert len(payloads) > 0


def test_load_nonexistent_payload():
    from utils.payload_loader import load_payloads
    result = load_payloads("nonexistent_payload_xyz")
    assert result == []


def test_list_available():
    from utils.payload_loader import list_available
    available = list_available()
    assert "payloads" in available
    assert "wordlists" in available
    assert isinstance(available["payloads"], list)


# ─── Test: Database ───────────────────────────────────────────────────────────

def test_database_create_and_retrieve():
    from database.db import Database
    from core.finding import Finding

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path=db_path)

        # Buat scan
        scan_id = db.create_scan(
            target="https://example.com",
            config={"modules": "sqli,xss", "target_url": "https://example.com"},
        )
        assert isinstance(scan_id, int)
        assert scan_id > 0

        # Ambil scan
        scan = db.get_scan(scan_id)
        assert scan is not None
        assert scan["target"] == "https://example.com"
        assert scan["status"] == "running"

        # Simpan finding
        f = Finding.from_cvss(
            cvss_score=9.8,
            title="SQL Injection Test",
            vuln_type="sqli",
            url="https://example.com/?id=1",
            parameter="id",
            module="sqli",
        )
        finding_id = db.save_finding(scan_id, f)
        assert finding_id > 0

        # Finish scan
        db.finish_scan(scan_id, total_findings=1)
        scan = db.get_scan(scan_id)
        assert scan["status"] == "completed"
        assert scan["total_findings"] == 1

        # Ambil findings
        findings = db.get_findings(scan_id)
        assert len(findings) == 1
        assert findings[0]["title"] == "SQL Injection Test"
        assert findings[0]["severity"] == "CRITICAL"

        # Stats
        stats = db.get_finding_stats(scan_id)
        assert stats.get("CRITICAL") == 1


def test_database_get_all_scans():
    from database.db import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(db_path=Path(tmpdir) / "test.db")
        db.create_scan("https://target1.com", {"modules": "sqli"})
        db.create_scan("https://target2.com", {"modules": "xss"})

        all_scans = db.get_all_scans()
        assert len(all_scans) == 2


def test_database_delete_scan():
    from database.db import Database

    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(db_path=Path(tmpdir) / "test.db")
        scan_id = db.create_scan("https://example.com", {"modules": "sqli"})
        db.delete_scan(scan_id)
        assert db.get_scan(scan_id) is None


# ─── Test: Module Injection - SQLi Heuristics ─────────────────────────────────

def test_sqli_error_detection():
    """Test regex deteksi error SQL."""
    import re
    from modules.injection.sqli import _SQL_ERROR_RE

    assert _SQL_ERROR_RE.search("You have an error in your SQL syntax")
    assert _SQL_ERROR_RE.search("Warning: mysql_fetch_array()")
    assert _SQL_ERROR_RE.search("ORA-12345: invalid query")
    assert not _SQL_ERROR_RE.search("Everything is fine")


def test_xss_canary_in_response():
    """Test logika deteksi XSS reflected."""
    from modules.injection.xss import _payload_reflected
    body = '<html><body><script>ABYSSXSS1234</script></body></html>'
    assert _payload_reflected(body, "<script>ABYSSXSS1234</script>", "ABYSSXSS1234")
    assert not _payload_reflected("<html>safe content</html>", "<script>evil</script>", "ABYSSXSS9999")


def test_ssrf_param_detection():
    """Test deteksi parameter SSRF-prone."""
    from modules.network.ssrf import _is_ssrf_param
    assert _is_ssrf_param("url")
    assert _is_ssrf_param("redirect_url")
    assert _is_ssrf_param("fetch_url")
    assert _is_ssrf_param("callback")
    assert not _is_ssrf_param("username")
    assert not _is_ssrf_param("page_size")


def test_redirect_param_detection():
    """Test deteksi parameter open redirect-prone."""
    from modules.network.open_redirect import _is_redirect_param
    assert _is_redirect_param("redirect")
    assert _is_redirect_param("next")
    assert _is_redirect_param("return_url")
    assert _is_redirect_param("goto")
    assert not _is_redirect_param("id")
    assert not _is_redirect_param("search")


# ─── Test: Reporter ────────────────────────────────────────────────────────────

def test_reporter_json():
    from database.db import Database
    from reporting.reporter import Reporter
    from core.finding import Finding

    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(db_path=Path(tmpdir) / "test.db")
        scan_id = db.create_scan("https://example.com", {"modules": "sqli"})

        f = Finding.from_cvss(
            cvss_score=7.5,
            title="Test Finding",
            vuln_type="sqli",
            url="https://example.com",
            module="sqli",
        )
        db.save_finding(scan_id, f)
        db.finish_scan(scan_id, 1)

        reporter = Reporter(db)
        out_path = str(Path(tmpdir) / "report.json")
        result = reporter.generate(scan_id, "json", out_path)

        import json
        with open(result) as fp:
            data = json.load(fp)

        assert data["scan"]["target"] == "https://example.com"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["title"] == "Test Finding"


def test_reporter_html():
    from database.db import Database
    from reporting.reporter import Reporter
    from core.finding import Finding

    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(db_path=Path(tmpdir) / "test.db")
        scan_id = db.create_scan("https://example.com", {"modules": "xss"})
        db.finish_scan(scan_id, 0)

        reporter = Reporter(db)
        out_path = str(Path(tmpdir) / "report.html")
        result = reporter.generate(scan_id, "html", out_path)

        content = Path(result).read_text(encoding="utf-8")
        assert "ABYSSFORGE" in content
        assert "example.com" in content
        assert "<!DOCTYPE html>" in content


# ─── Test: Misconfig - Security Headers ───────────────────────────────────────

def test_has_csrf_token_form():
    from modules.network.csrf import _has_csrf_token
    form_with = {"inputs": ["username", "password", "csrfmiddlewaretoken"]}
    form_without = {"inputs": ["username", "password"]}
    assert _has_csrf_token(form_with) is True
    assert _has_csrf_token(form_without) is False


def test_weak_cookie_detection():
    from modules.broken_auth.auth_check import _is_weak_cookie_value
    assert _is_weak_cookie_value("12345") is True
    assert _is_weak_cookie_value("admin") is True
    # Nilai kuat tidak boleh terdeteksi lemah
    assert _is_weak_cookie_value("a9f8d3e7c2b1a4f6d5e8c3b2a7f1e0d4") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
