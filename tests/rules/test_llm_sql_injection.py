"""Tests for LS003: confirmed LLM/user -> SQL injection (graduated to stable).

LS003 is taint-gated: it reports a dynamic SQL query only when an interpolated
value is taint-confirmed to carry LLM or user input. Blanket dynamic-SQL
detection (regardless of source) is intentionally left to general linters such
as Bandit (B608).
"""

from __future__ import annotations

from pathlib import Path

from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
from llm_seclint.core.finding import Finding
from llm_seclint.rules.python.llm_sql_injection import LlmSqlInjectionRule
from tests.conftest import run_rule_on_code


def _rule() -> LlmSqlInjectionRule:
    return LlmSqlInjectionRule()


def _scan(code: str) -> list[Finding]:
    findings, _ = PythonAnalyzer([_rule()]).analyze(code, Path("app.py"))
    return [f for f in findings if f.rule_id == "LS003"]


# Taint-source prefixes for the flows under test.
_USER = "raw = request.args.get('q')\n"
_LLM = "raw = litellm.completion(model='m').content\n"


class TestLs003ConfirmedFlows:
    def test_fstring_user(self) -> None:
        f = _scan(_USER + "cursor.execute(f\"SELECT * FROM users WHERE n='{raw}'\")\n")
        assert len(f) == 1
        assert f[0].taint_source == "user"
        assert "confirmed" in f[0].message.lower()

    def test_concat_llm(self) -> None:
        f = _scan(_LLM + 'cursor.execute("SELECT * FROM users WHERE id = " + raw)\n')
        assert len(f) == 1
        assert f[0].taint_source == "llm"

    def test_format_user(self) -> None:
        f = _scan(_USER + 'db.execute("DELETE FROM logs WHERE id = {}".format(raw))\n')
        assert len(f) == 1
        assert f[0].taint_source == "user"

    def test_percent_user(self) -> None:
        f = _scan(_USER + "cursor.execute(\"UPDATE users SET n = '%s'\" % raw)\n")
        assert len(f) == 1


class TestLs003Graduated:
    def test_unconfirmed_dynamic_sql_not_reported(self) -> None:
        # Graduation: a dynamic SQL value with no traced untrusted source is no
        # longer reported (that is Bandit B608's job, not this LLM-focused tool).
        f = _scan('cursor.execute(f"SELECT * FROM users WHERE id = {local_id}")\n')
        assert len(f) == 0

    def test_stability_is_stable(self) -> None:
        assert _rule().stability == "stable"

    def test_safe_parameterized(self) -> None:
        f = _scan(_USER + 'cursor.execute("SELECT * FROM u WHERE id = ?", (raw,))\n')
        assert len(f) == 0

    def test_safe_static_query(self) -> None:
        assert _scan('cursor.execute("SELECT COUNT(*) FROM users")\n') == []

    def test_non_sql_execute(self) -> None:
        assert _scan(_USER + "task.execute(raw)\n") == []

    def test_no_taint_context_reports_nothing(self) -> None:
        # Called directly without a taint context, graduated LS003 has nothing
        # to confirm, so it stays silent.
        code = "cursor.execute(f\"SELECT * FROM users WHERE id = '{x}'\")"
        assert run_rule_on_code(_rule(), code) == []
