"""Tests for text, JSON, and SARIF formatters."""

from __future__ import annotations

import json
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.formatters.json_fmt import JsonFormatter
from llm_seclint.formatters.sarif import SarifFormatter
from llm_seclint.formatters.text import TextFormatter


def _make_finding(**overrides: object) -> Finding:
    defaults = dict(
        rule_id="SEC001",
        rule_name="test-rule",
        severity=Severity.HIGH,
        message="Test vulnerability found",
        file_path=Path("src/app.py"),
        line=42,
    )
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestTextFormatter:
    """Tests for TextFormatter."""

    def test_formats_findings_correctly(self) -> None:
        finding = _make_finding()
        fmt = TextFormatter(use_color=False)

        output = fmt.format([finding], elapsed=1.23)

        assert "src/app.py" in output
        assert "SEC001" in output
        assert "Test vulnerability found" in output

    def test_no_ansi_codes_without_color(self) -> None:
        finding = _make_finding()
        fmt = TextFormatter(use_color=False)

        output = fmt.format([finding], elapsed=0.5)

        # ANSI escape codes start with \x1b[
        assert "\x1b[" not in output

    def test_empty_findings(self) -> None:
        fmt = TextFormatter(use_color=False)
        output = fmt.format([], elapsed=0.1)

        assert "No security issues found" in output

    def test_grouped_summary_shown_for_5_plus_similar(self) -> None:
        """When 5+ findings share the same rule and directory, a grouped summary appears."""
        findings = [
            _make_finding(
                rule_id="LS003",
                message="SQL injection via f-string",
                file_path=Path(f"core/rag/vdb/driver{i}.py"),
                line=10 + i,
            )
            for i in range(6)
        ]
        fmt = TextFormatter(use_color=False, show_groups=True)
        output = fmt.format(findings, elapsed=0.5)

        assert "Grouped summary" in output
        assert "LS003" in output
        assert "6 similar findings" in output
        assert "core/rag/vdb/" in output
        assert "SQL injection via f-string" in output

    def test_grouped_summary_hidden_below_threshold(self) -> None:
        """Fewer than 5 findings in the same group should not produce a grouped summary."""
        findings = [
            _make_finding(
                rule_id="LS003",
                message="SQL injection via f-string",
                file_path=Path(f"core/rag/vdb/driver{i}.py"),
                line=10 + i,
            )
            for i in range(4)
        ]
        fmt = TextFormatter(use_color=False, show_groups=True)
        output = fmt.format(findings, elapsed=0.5)

        assert "Grouped summary" not in output

    def test_grouped_summary_hidden_with_no_group(self) -> None:
        """--no-group (show_groups=False) should suppress the grouped summary."""
        findings = [
            _make_finding(
                rule_id="LS003",
                message="SQL injection via f-string",
                file_path=Path(f"core/rag/vdb/driver{i}.py"),
                line=10 + i,
            )
            for i in range(6)
        ]
        fmt = TextFormatter(use_color=False, show_groups=False)
        output = fmt.format(findings, elapsed=0.5)

        assert "Grouped summary" not in output


class TestJsonFormatter:
    """Tests for JsonFormatter."""

    def test_outputs_valid_json(self) -> None:
        finding = _make_finding()
        fmt = JsonFormatter()

        output = fmt.format([finding], elapsed=1.0)
        parsed = json.loads(output)

        assert isinstance(parsed, dict)

    def test_includes_all_finding_fields(self) -> None:
        finding = _make_finding()
        fmt = JsonFormatter()

        output = fmt.format([finding], elapsed=1.0)
        parsed = json.loads(output)

        result = parsed["findings"][0]
        assert result["rule_id"] == "SEC001"
        assert result["rule_name"] == "test-rule"
        assert result["severity"] == "HIGH"
        assert result["message"] == "Test vulnerability found"
        assert result["file"] == "src/app.py"
        assert result["line"] == 42

    def test_empty_findings(self) -> None:
        fmt = JsonFormatter()
        output = fmt.format([], elapsed=0.1)
        parsed = json.loads(output)

        assert parsed["findings"] == []
        assert parsed["summary"]["total"] == 0


class TestSarifFormatter:
    """Tests for SarifFormatter."""

    def test_outputs_valid_json(self) -> None:
        finding = _make_finding()
        fmt = SarifFormatter()

        output = fmt.format([finding], elapsed=1.0)
        parsed = json.loads(output)

        assert isinstance(parsed, dict)

    def test_has_correct_schema_version(self) -> None:
        finding = _make_finding()
        fmt = SarifFormatter()

        output = fmt.format([finding], elapsed=1.0)
        parsed = json.loads(output)

        assert parsed["version"] == "2.1.0"
        assert "$schema" in parsed
        assert "sarif-schema-2.1.0" in parsed["$schema"]

    def test_results_map_findings_correctly(self) -> None:
        finding = _make_finding(
            cwe_id="CWE-798",
            owasp_llm="LLM06",
            col=5,
        )
        fmt = SarifFormatter()

        output = fmt.format([finding], elapsed=1.0)
        parsed = json.loads(output)

        run = parsed["runs"][0]

        # Check tool driver
        driver = run["tool"]["driver"]
        assert driver["name"] == "llm-seclint"
        assert len(driver["rules"]) == 1
        rule = driver["rules"][0]
        assert rule["id"] == "SEC001"
        assert rule["name"] == "test-rule"
        assert "helpUri" in rule
        assert "798" in rule["helpUri"]

        # Check result
        assert len(run["results"]) == 1
        result = run["results"][0]
        assert result["ruleId"] == "SEC001"
        assert result["level"] == "error"  # HIGH -> error
        assert result["message"]["text"] == "Test vulnerability found"

        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/app.py"
        assert loc["region"]["startLine"] == 42
        assert loc["region"]["startColumn"] == 5

    def test_severity_mapping(self) -> None:
        fmt = SarifFormatter()

        findings = [
            _make_finding(rule_id="R1", severity=Severity.CRITICAL),
            _make_finding(rule_id="R2", severity=Severity.HIGH),
            _make_finding(rule_id="R3", severity=Severity.MEDIUM),
            _make_finding(rule_id="R4", severity=Severity.LOW),
            _make_finding(rule_id="R5", severity=Severity.INFO),
        ]
        output = fmt.format(findings, elapsed=0.5)
        parsed = json.loads(output)

        levels = [r["level"] for r in parsed["runs"][0]["results"]]
        assert levels == ["error", "error", "warning", "note", "note"]

    def test_empty_findings_produces_valid_structure(self) -> None:
        fmt = SarifFormatter()

        output = fmt.format([], elapsed=0.1)
        parsed = json.loads(output)

        assert parsed["version"] == "2.1.0"
        assert "$schema" in parsed
        assert len(parsed["runs"]) == 1

        run = parsed["runs"][0]
        assert run["tool"]["driver"]["name"] == "llm-seclint"
        assert run["tool"]["driver"]["rules"] == []
        assert run["results"] == []


class TestTaintSurfacing:
    """The confirmed-dataflow note and structured taint_source reach output."""

    def test_text_formatter_surfaces_confirmed_note(self) -> None:
        finding = _make_finding(
            rule_id="LS006",
            message="Dynamic input passed to eval() — confirmed LLM→sink dataflow",
            taint_source="llm",
        )
        out = TextFormatter(use_color=False).format([finding], elapsed=0.0)
        assert "confirmed" in out.lower()

    def test_json_formatter_includes_taint_source(self) -> None:
        finding = _make_finding(rule_id="LS006", taint_source="llm")
        out = JsonFormatter().format([finding], elapsed=0.0)
        data = json.loads(out)
        assert data["findings"][0]["taint_source"] == "llm"
