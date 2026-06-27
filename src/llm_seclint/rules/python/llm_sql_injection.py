"""LS003: Detect LLM output used in SQL queries without parameterization."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# SQL execution function names
_SQL_EXEC_NAMES = {"execute", "executemany", "executescript", "raw", "execute_sql"}

# SQL keywords that identify a string as a SQL query
_SQL_KEYWORDS = {"select", "insert", "update", "delete", "drop", "create", "alter", "from", "where"}


class LlmSqlInjectionRule(Rule):
    """Detect LLM output concatenated into SQL queries."""

    rule_id = "LS003"
    rule_name = "llm-to-sql-injection"
    severity = Severity.CRITICAL
    # Flags any dynamic f-string/concat SQL regardless of whether the value is
    # LLM-derived, so it over-reports (and overlaps Bandit B608). Off by default;
    # enable with --experimental.
    stability = "experimental"
    description = (
        "LLM output is concatenated into a SQL query string. "
        "This allows SQL injection if the LLM output is attacker-influenced."
    )
    cwe_id = "CWE-89"
    owasp_llm = "LLM02: Insecure Output Handling"

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str], taint: object | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Check if this is a SQL execute call
            func_name = self._get_func_name(node)
            if func_name not in _SQL_EXEC_NAMES:
                continue

            # Check the first argument (the query)
            if not node.args:
                continue

            query_arg = node.args[0]

            # Case 1: f-string with SQL keywords and dynamic values
            if isinstance(query_arg, ast.JoinedStr):
                if self._fstring_has_sql(query_arg) and self._fstring_has_variables(query_arg):
                    findings.append(
                        self._make_finding(
                            file_path,
                            node.lineno,
                            "LLM/dynamic output interpolated into SQL query via f-string",
                            source_lines,
                            col=node.col_offset,
                            fix_suggestion="Use parameterized queries: cursor.execute('SELECT ... WHERE x = ?', (value,))",
                        )
                    )

            # Case 2: String concatenation with + operator
            elif isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Add):
                if self._binop_has_sql(query_arg):
                    findings.append(
                        self._make_finding(
                            file_path,
                            node.lineno,
                            "Dynamic output concatenated into SQL query via + operator",
                            source_lines,
                            col=node.col_offset,
                            fix_suggestion="Use parameterized queries instead of string concatenation",
                        )
                    )

            # Case 3: .format() on a SQL string
            elif (
                isinstance(query_arg, ast.Call)
                and isinstance(query_arg.func, ast.Attribute)
                and query_arg.func.attr == "format"
                and isinstance(query_arg.func.value, ast.Constant)
                and isinstance(query_arg.func.value.value, str)
                and self._str_has_sql(query_arg.func.value.value)
            ):
                findings.append(
                    self._make_finding(
                        file_path,
                        node.lineno,
                        "Dynamic output injected into SQL query via .format()",
                        source_lines,
                        col=node.col_offset,
                        fix_suggestion="Use parameterized queries instead of .format()",
                    )
                )

            # Case 4: %-formatting
            elif (
                isinstance(query_arg, ast.BinOp)
                and isinstance(query_arg.op, ast.Mod)
                and isinstance(query_arg.left, ast.Constant)
                and isinstance(query_arg.left.value, str)
                and self._str_has_sql(query_arg.left.value)
            ):
                findings.append(
                    self._make_finding(
                        file_path,
                        node.lineno,
                        "Dynamic output injected into SQL query via %-formatting",
                        source_lines,
                        col=node.col_offset,
                        fix_suggestion="Use parameterized queries instead of %-formatting",
                    )
                )

        return findings

    @staticmethod
    def _get_func_name(node: ast.Call) -> str:
        """Get the function/method name from a Call node."""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    @staticmethod
    def _str_has_sql(text: str) -> bool:
        """Check if a string contains SQL keywords."""
        text_lower = text.lower()
        return any(kw in text_lower for kw in _SQL_KEYWORDS)

    @staticmethod
    def _fstring_has_sql(node: ast.JoinedStr) -> bool:
        """Check if an f-string contains SQL keywords in its static parts."""
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                if LlmSqlInjectionRule._str_has_sql(value.value):
                    return True
        return False

    @staticmethod
    def _fstring_has_variables(node: ast.JoinedStr) -> bool:
        """Check if an f-string has any interpolated variables."""
        return any(isinstance(v, ast.FormattedValue) for v in node.values)

    @staticmethod
    def _binop_has_sql(node: ast.BinOp) -> bool:
        """Check if a BinOp chain contains SQL keywords in string parts."""
        parts = LlmSqlInjectionRule._collect_binop_parts(node)
        # Need at least one non-constant part (dynamic/variable)
        has_variable = any(
            not (isinstance(p, ast.Constant) and isinstance(p.value, str))
            for p in parts
        )
        return has_variable and any(
            isinstance(p, ast.Constant)
            and isinstance(p.value, str)
            and LlmSqlInjectionRule._str_has_sql(p.value)
            for p in parts
        )

    @staticmethod
    def _collect_binop_parts(node: ast.expr) -> list[ast.expr]:
        """Recursively collect parts of a BinOp(Add) chain."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = LlmSqlInjectionRule._collect_binop_parts(node.left)
            right = LlmSqlInjectionRule._collect_binop_parts(node.right)
            return left + right
        return [node]
