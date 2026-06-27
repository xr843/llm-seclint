"""Tests for LS007: Server-Side Template Injection detection."""

from __future__ import annotations

from llm_seclint.rules.python.ssti import SSTIRule
from tests.conftest import run_rule_on_code


def _rule() -> SSTIRule:
    return SSTIRule()


class TestSSTI:
    def test_render_template_string_dynamic(self) -> None:
        code = "render_template_string(user_input)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS007"

    def test_jinja2_template_dynamic(self) -> None:
        code = "jinja2.Template(user_data)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS007"

    def test_env_from_string_dynamic(self) -> None:
        code = "env.from_string(user_data)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS007"

    def test_render_template_string_static(self) -> None:
        code = 'render_template_string("static html")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_sandboxed_environment_safe(self) -> None:
        code = "SandboxedEnvironment().from_string(data)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_immutable_sandboxed_environment_safe(self) -> None:
        code = "ImmutableSandboxedEnvironment().from_string(data)"
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_render_template_safe(self) -> None:
        code = 'render_template("index.html")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0


class TestLs007TaintConfirmation:
    def test_confirmed_llm_to_template(self) -> None:
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        code = (
            "r = litellm.completion(model='m')\n"
            "t = r.content\n"
            "render_template_string(t)\n"
        )
        findings, _ = PythonAnalyzer([_rule()]).analyze(code, Path("app.py"))
        f = [x for x in findings if x.rule_id == "LS007"][0]
        assert f.taint_source == "llm"
        assert "confirmed" in f.message.lower()

    def test_plain_dynamic_unchanged(self) -> None:
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        findings, _ = PythonAnalyzer([_rule()]).analyze(
            "render_template_string(t)\n", Path("app.py")
        )
        f = [x for x in findings if x.rule_id == "LS007"][0]
        assert f.taint_source == ""
