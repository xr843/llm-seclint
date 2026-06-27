"""Tests for LS005: LLM output to path traversal detection."""

from __future__ import annotations

from llm_seclint.rules.python.llm_path_traversal import LlmPathTraversalRule
from tests.conftest import run_rule_on_code


def _rule() -> LlmPathTraversalRule:
    return LlmPathTraversalRule()


class TestLlmPathTraversal:
    def test_open_variable(self) -> None:
        code = 'open(llm_response)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS005"

    def test_open_with_context(self) -> None:
        code = '''
with open(filename) as f:
    data = f.read()
'''
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_path_constructor_not_flagged(self) -> None:
        """Path() is navigation/construction, not dangerous by itself."""
        code = 'Path(llm_output)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_os_path_join_not_flagged(self) -> None:
        """os.path.join() is path construction, not dangerous by itself."""
        code = 'os.path.join(base_dir, user_filename)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_shutil_copy(self) -> None:
        code = 'shutil.copy(source, destination)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_os_remove(self) -> None:
        code = 'os.remove(filepath)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_safe_open_static(self) -> None:
        code = 'open("config.json")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_path_static(self) -> None:
        """Path() with static arg is safe (Path() is not flagged at all now)."""
        code = 'Path("/etc/config")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_os_listdir_not_flagged(self) -> None:
        """os.listdir() is read-only navigation, not dangerous."""
        code = 'os.listdir(user_dir)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_os_makedirs_not_flagged(self) -> None:
        """os.makedirs() removed from detection to reduce noise."""
        code = 'os.makedirs(output_dir)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_non_file_function(self) -> None:
        code = 'mylib.open(some_variable)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_sanitization_functions_not_flagged(self) -> None:
        """Sanitization/check functions should not trigger findings."""
        safe_calls = [
            'os.path.realpath(user_input)',
            'os.path.abspath(user_input)',
            'os.path.exists(user_input)',
            'os.path.isfile(user_input)',
            'os.path.isdir(user_input)',
            'os.stat(user_input)',
        ]
        for code in safe_calls:
            findings = run_rule_on_code(_rule(), code)
            assert len(findings) == 0, f"{code} should not trigger a finding"


class TestLs005TaintConfirmation:
    def test_confirmed_llm_to_path(self) -> None:
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        code = "r = litellm.completion(model='m')\np = r.content\nopen(p)\n"
        findings, _ = PythonAnalyzer([_rule()]).analyze(code, Path("app.py"))
        f = [x for x in findings if x.rule_id == "LS005"][0]
        assert f.taint_source == "llm"
        assert "confirmed" in f.message.lower()

    def test_plain_dynamic_unchanged(self) -> None:
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        findings, _ = PythonAnalyzer([_rule()]).analyze("open(p)\n", Path("app.py"))
        f = [x for x in findings if x.rule_id == "LS005"][0]
        assert f.taint_source == ""
