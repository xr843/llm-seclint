"""LS005: Detect LLM output used as file paths without sanitization."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# Built-in/stdlib functions that open or manipulate file paths
_FILE_FUNCS: dict[str, set[str]] = {
    "": {"open"},  # built-in open()
    "os": {"remove", "unlink", "rmdir", "rename"},
    "shutil": {"copy", "copy2", "copytree", "move", "rmtree"},
}


class LlmPathTraversalRule(Rule):
    """Detect LLM output used as file paths."""

    rule_id = "LS005"
    rule_name = "llm-to-path-traversal"
    severity = Severity.MEDIUM
    description = (
        "LLM output is used as a file path. "
        "An attacker may use prompt injection to achieve path traversal."
    )
    cwe_id = "CWE-22"
    owasp_llm = "LLM02: Insecure Output Handling"

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str], taint: object | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_info = self._classify_call(node)
            if func_info is None:
                continue

            func_display = func_info

            # Check if any argument is dynamic
            src = self._confirmed_taint(node.args, taint)
            for arg in node.args:
                if self._is_dynamic(arg):
                    message = f"Dynamic value passed to {func_display}"
                    if src:
                        message += f" — confirmed {src.upper()}→sink dataflow"
                    findings.append(
                        self._make_finding(
                            file_path,
                            node.lineno,
                            message,
                            source_lines,
                            col=node.col_offset,
                            fix_suggestion=(
                                "Validate and sanitize file paths from LLM output. "
                                "Use os.path.realpath() and check against an allowed base directory."
                            ),
                            taint_source=src,
                        )
                    )
                    break  # One finding per call is enough

        return findings

    @staticmethod
    def _classify_call(node: ast.Call) -> str | None:
        """Check if a call is a file path function. Returns display name or None."""
        # Built-in open()
        if isinstance(node.func, ast.Name):
            if node.func.id == "open":
                return "open()"
            return None

        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr

            # module.func pattern (e.g. os.remove, shutil.copy)
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                if module in _FILE_FUNCS and attr in _FILE_FUNCS[module]:
                    return f"{module}.{attr}()"
                return None

        return None

    @staticmethod
    def _is_dynamic(node: ast.expr) -> bool:
        """Check if a node represents dynamic content."""
        if isinstance(node, ast.Constant):
            return False
        return True
