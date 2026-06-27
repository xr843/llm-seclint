"""LS007: Detect Server-Side Template Injection (SSTI) vulnerabilities."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# Functions that are dangerous when called with dynamic arguments
_DANGEROUS_FUNCS = {"render_template_string", "from_string"}

# Safe template environments (sandboxed)
_SAFE_ENVIRONMENTS = {"SandboxedEnvironment", "ImmutableSandboxedEnvironment"}


class SSTIRule(Rule):
    """Detect unsafe Jinja2/Flask template rendering with dynamic content."""

    rule_id = "LS007"
    rule_name = "server-side-template-injection"
    severity = Severity.CRITICAL
    description = (
        "Dynamic content passed to template engine without sandboxing"
    )
    cwe_id = "CWE-1336"
    owasp_llm = "LLM02: Insecure Output Handling"

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str], taint: object | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            result = self._classify_call(node)
            if result is None:
                continue

            func_display, suggestion = result

            # Check if any argument is dynamic
            has_dynamic = any(self._is_dynamic(arg) for arg in node.args)
            if not has_dynamic:
                continue

            src = self._confirmed_taint(node.args, taint)
            message = f"Dynamic input passed to {func_display}"
            if src:
                message += f" — confirmed {src.upper()}→sink dataflow"

            findings.append(
                self._make_finding(
                    file_path,
                    node.lineno,
                    message,
                    source_lines,
                    col=node.col_offset,
                    fix_suggestion=suggestion,
                    taint_source=src,
                )
            )

        return findings

    @staticmethod
    def _classify_call(node: ast.Call) -> tuple[str, str] | None:
        """Classify a call as dangerous template rendering. Returns (display, suggestion) or None."""
        func = node.func

        # render_template_string(user_input) — bare function call
        if isinstance(func, ast.Name) and func.id == "render_template_string":
            return (
                "render_template_string()",
                "Use render_template() with a file-based template instead of "
                "render_template_string() with dynamic content.",
            )

        # module.func() patterns: jinja2.Template(), env.from_string()
        if isinstance(func, ast.Attribute):
            attr = func.attr
            value = func.value

            # jinja2.Template(user_input)
            if attr == "Template" and isinstance(value, ast.Name) and value.id == "jinja2":
                return (
                    "jinja2.Template()",
                    "Avoid constructing Jinja2 templates from dynamic content. "
                    "Use file-based templates or SandboxedEnvironment.",
                )

            # env.from_string(user_input) — check receiver is not a sandboxed env
            if attr == "from_string":
                # Check if receiver is a call to a safe environment constructor
                if SSTIRule._is_sandboxed_receiver(value):
                    return None
                return (
                    ".from_string()",
                    "Avoid constructing templates from dynamic strings. "
                    "Use SandboxedEnvironment or file-based templates.",
                )

        return None

    @staticmethod
    def _is_sandboxed_receiver(node: ast.expr) -> bool:
        """Check if a node represents a sandboxed environment instance."""
        # SandboxedEnvironment().from_string(...)
        if isinstance(node, ast.Call):
            callee = node.func
            if isinstance(callee, ast.Name) and callee.id in _SAFE_ENVIRONMENTS:
                return True
            if isinstance(callee, ast.Attribute) and callee.attr in _SAFE_ENVIRONMENTS:
                return True
        # Variable named with sandbox hint — can't reliably detect, skip
        return False

    @staticmethod
    def _is_dynamic(node: ast.expr) -> bool:
        """Check if a node is dynamic (not a constant)."""
        if isinstance(node, ast.Constant):
            return False
        return True
