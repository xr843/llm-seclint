"""Tests for LS006: Insecure deserialization detection."""

from __future__ import annotations

from llm_seclint.rules.python.insecure_deserialization import (
    InsecureDeserializationRule,
)
from tests.conftest import run_rule_on_code


def _rule() -> InsecureDeserializationRule:
    return InsecureDeserializationRule()


class TestInsecureDeserialization:
    def test_eval_variable(self) -> None:
        code = 'result = eval(llm_response)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS006"

    def test_exec_variable(self) -> None:
        code = 'exec(code_from_llm)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_pickle_loads(self) -> None:
        code = 'data = pickle.loads(response_bytes)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_pickle_load(self) -> None:
        code = 'data = pickle.load(file_obj)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_yaml_unsafe_load(self) -> None:
        code = 'data = yaml.unsafe_load(response_text)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_yaml_load_full_loader(self) -> None:
        code = 'data = yaml.load(text, Loader=yaml.FullLoader)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_yaml_load_unsafe_loader(self) -> None:
        code = 'data = yaml.load(text, Loader=yaml.UnsafeLoader)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_marshal_loads(self) -> None:
        code = 'obj = marshal.loads(data)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_safe_eval_literal(self) -> None:
        code = 'eval("1 + 2")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_json_loads(self) -> None:
        code = 'data = json.loads(response_text)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_yaml_safe_load(self) -> None:
        code = 'data = yaml.safe_load(text)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_yaml_load_safe_loader(self) -> None:
        code = 'data = yaml.load(text, Loader=yaml.SafeLoader)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_compile_variable(self) -> None:
        code = 'compiled = compile(source_code, "<string>", "exec")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1


class TestLs006TaintConfirmation:
    """Taint-confirmed LLM->sink dataflow is marked; plain dynamic unchanged."""

    def test_confirmed_llm_dataflow(self) -> None:
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        code = "r = litellm.completion(model='m')\nx = r.content\neval(x)\n"
        findings, _ = PythonAnalyzer([_rule()]).analyze(code, Path("a.py"))
        f = [f for f in findings if f.rule_id == "LS006"][0]
        assert f.taint_source == "llm"
        assert "confirmed" in f.message.lower()

    def test_plain_dynamic_unchanged(self) -> None:
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        code = "x = get_local()\neval(x)\n"
        findings, _ = PythonAnalyzer([_rule()]).analyze(code, Path("a.py"))
        f = [f for f in findings if f.rule_id == "LS006"][0]
        assert f.taint_source == ""
        assert "confirmed" not in f.message.lower()
