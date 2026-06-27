"""Tests for the Finding dataclass."""

from __future__ import annotations

from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity


def test_finding_taint_source_defaults_empty_and_serializes() -> None:
    f = Finding(
        rule_id="LS006",
        rule_name="x",
        severity=Severity.HIGH,
        message="m",
        file_path=Path("a.py"),
        line=1,
    )
    assert f.taint_source == ""
    assert f.to_dict()["taint_source"] == ""

    f2 = Finding(
        rule_id="LS006",
        rule_name="x",
        severity=Severity.HIGH,
        message="m",
        file_path=Path("a.py"),
        line=1,
        taint_source="llm",
    )
    assert f2.to_dict()["taint_source"] == "llm"
