"""Tests for LS008: XXE XML Parsing detection."""

from __future__ import annotations

from llm_seclint.rules.python.xxe import XXERule
from tests.conftest import run_rule_on_code


def _rule() -> XXERule:
    return XXERule()


class TestXXE:
    def test_etree_parse_dynamic(self) -> None:
        code = "etree.parse(user_file)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS008"

    def test_etree_fromstring_dynamic(self) -> None:
        code = "etree.fromstring(data)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS008"

    def test_elementtree_parse_dynamic(self) -> None:
        code = "xml.etree.ElementTree.parse(path)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS008"

    def test_sax_parsestring_dynamic(self) -> None:
        code = "xml.sax.parseString(data)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS008"

    def test_minidom_parse_dynamic(self) -> None:
        code = "minidom.parse(user_file)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS008"

    def test_defusedxml_safe(self) -> None:
        code = "defusedxml.parse(data)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_etree_parse_static(self) -> None:
        code = 'etree.parse("static.xml")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_sax_parse_dynamic(self) -> None:
        code = "sax.parse(user_file)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS008"


class TestLs008TaintConfirmation:
    def test_confirmed_llm_to_xml(self) -> None:
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        code = "r = litellm.completion(model='m')\nx = r.content\netree.parse(x)\n"
        findings, _ = PythonAnalyzer([_rule()]).analyze(code, Path("app.py"))
        f = [x for x in findings if x.rule_id == "LS008"][0]
        assert f.taint_source == "llm"
        assert "confirmed" in f.message.lower()

    def test_plain_dynamic_unchanged(self) -> None:
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        findings, _ = PythonAnalyzer([_rule()]).analyze(
            "etree.parse(x)\n", Path("app.py")
        )
        f = [x for x in findings if x.rule_id == "LS008"][0]
        assert f.taint_source == ""
