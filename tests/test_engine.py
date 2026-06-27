"""Tests for the scan engine."""

from __future__ import annotations

from pathlib import Path

from llm_seclint.config import ScanConfig
from llm_seclint.core.engine import ScanEngine


def test_engine_scans_files(tmp_path: Path) -> None:
    py_file = tmp_path / "test.py"
    py_file.write_text('OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')

    engine = ScanEngine()
    result = engine.scan([tmp_path])
    assert len(result.findings) >= 1
    assert result.findings[0].rule_id == "LS001"
    assert result.scanned_count >= 1


def test_engine_respects_ignore_rules(tmp_path: Path) -> None:
    py_file = tmp_path / "test.py"
    py_file.write_text('OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')

    config = ScanConfig(ignore_rules=["LS001"])
    engine = ScanEngine(config)
    result = engine.scan([tmp_path])
    assert all(f.rule_id != "LS001" for f in result.findings)


def test_engine_no_files(tmp_path: Path) -> None:
    engine = ScanEngine()
    result = engine.scan([tmp_path])
    assert result.findings == []


def test_engine_skips_syntax_errors(tmp_path: Path) -> None:
    py_file = tmp_path / "bad.py"
    py_file.write_text("def foo(\n")  # syntax error

    engine = ScanEngine()
    result = engine.scan([tmp_path])
    assert result.findings == []
    assert len(result.skipped_files) == 1
    assert "SyntaxError" in result.skipped_files[0].reason


def test_engine_skips_unreadable_files(tmp_path: Path) -> None:
    py_file = tmp_path / "bad.py"
    py_file.write_bytes(b"\x80\x81\x82\x83")

    engine = ScanEngine()
    result = engine.scan([tmp_path])
    assert result.findings == []
    assert len(result.skipped_files) == 1
    assert "encoding error" in result.skipped_files[0].reason


def test_engine_get_rules_info() -> None:
    engine = ScanEngine()
    info = engine.get_rules_info()
    assert len(info) == 10
    ids = {r["id"] for r in info}
    assert ids == {
        "LS001", "LS002", "LS003", "LS004", "LS005",
        "LS006", "LS007", "LS008", "LS009", "LS010",
    }
    # Check that cwe_id is present in rules info
    assert all("cwe_id" in r for r in info)
    # Stability is exposed; LS002 is the remaining experimental rule (LS003
    # graduated to stable once it became taint-gated).
    stability = {r["id"]: r["stability"] for r in info}
    assert stability["LS002"] == "experimental"
    assert stability["LS003"] == "stable"
    assert stability["LS001"] == "stable"


def test_engine_skips_experimental_by_default(tmp_path: Path) -> None:
    py_file = tmp_path / "app.py"
    # Pure LS002 (experimental) trigger, no stable findings.
    py_file.write_text('prompt = f"You are a bot. User says: {user_input}"\n')

    assert ScanEngine().scan([tmp_path]).findings == []

    config = ScanConfig(include_experimental=True)
    findings = ScanEngine(config).scan([tmp_path]).findings
    assert any(f.rule_id == "LS002" for f in findings)


def test_engine_scans_single_file(tmp_path: Path) -> None:
    py_file = tmp_path / "app.py"
    py_file.write_text('key = eval(user_input)\n')

    engine = ScanEngine()
    result = engine.scan([py_file])
    assert len(result.findings) >= 1


def test_engine_deduplicates_findings() -> None:
    """Duplicate findings (same rule_id + file_path + line) are removed."""
    from llm_seclint.core.finding import Finding
    from llm_seclint.core.severity import Severity

    dup1 = Finding(
        rule_id="LS003",
        rule_name="sql-injection",
        severity=Severity.HIGH,
        message="SQL injection via f-string",
        file_path=Path("core/rag/vdb/driver.py"),
        line=10,
    )
    dup2 = Finding(
        rule_id="LS003",
        rule_name="sql-injection",
        severity=Severity.HIGH,
        message="SQL injection via f-string",
        file_path=Path("core/rag/vdb/driver.py"),
        line=10,
    )
    different = Finding(
        rule_id="LS003",
        rule_name="sql-injection",
        severity=Severity.HIGH,
        message="SQL injection via f-string",
        file_path=Path("core/rag/vdb/driver.py"),
        line=20,
    )

    result = ScanEngine._deduplicate([dup1, dup2, different])
    assert len(result) == 2
    assert result[0] is dup1
    assert result[1] is different
