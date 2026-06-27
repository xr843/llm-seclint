"""LS006: Detect insecure deserialization or code execution on LLM responses."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.analyzers.taint import TaintContext
from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# Dangerous built-in functions
_DANGEROUS_BUILTINS = {"eval", "exec", "compile"}

# Dangerous module.function patterns
_DANGEROUS_MODULE_FUNCS: dict[str, set[str]] = {
    "pickle": {"loads", "load"},
    "cPickle": {"loads", "load"},
    "shelve": {"open"},
    "marshal": {"loads", "load"},
    "yaml": {"load", "unsafe_load", "full_load"},
}

# yaml.load with unsafe Loaders
_UNSAFE_YAML_LOADERS = {"Loader", "UnsafeLoader", "FullLoader"}


class InsecureDeserializationRule(Rule):
    """Detect eval/exec/pickle/unsafe yaml on potentially LLM-sourced data."""

    rule_id = "LS006"
    rule_name = "insecure-deserialization"
    severity = Severity.HIGH
    description = (
        "Unsafe deserialization or code execution function called with dynamic input. "
        "If the input comes from an LLM, this enables arbitrary code execution."
    )
    cwe_id = "CWE-502"
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

            # If a dynamic argument is taint-confirmed to carry LLM/user output,
            # mark the finding as confirmed dataflow (enhancement only — a merely
            # dynamic argument is still reported with no taint source).
            src = ""
            if isinstance(taint, TaintContext):
                for arg in node.args:
                    confirmed = taint.is_tainted(arg)
                    if confirmed:
                        src = confirmed
                        break

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
        """Classify a call as dangerous deserialization. Returns (display, suggestion) or None."""
        # eval(), exec(), compile()
        if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_BUILTINS:
            name = node.func.id
            return (
                f"{name}()",
                f"Never use {name}() on data that may come from an LLM. "
                f"Use ast.literal_eval() for safe parsing, or json.loads() for JSON.",
            )

        # module.func() patterns
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id

                if module in _DANGEROUS_MODULE_FUNCS and attr in _DANGEROUS_MODULE_FUNCS[module]:
                    display = f"{module}.{attr}()"

                    # Special handling for yaml.load - check Loader kwarg
                    if module == "yaml" and attr == "load":
                        loader_safe = False
                        for kw in node.keywords:
                            if kw.arg == "Loader" and isinstance(kw.value, ast.Attribute):
                                if kw.value.attr == "SafeLoader":
                                    loader_safe = True
                                elif kw.value.attr in _UNSAFE_YAML_LOADERS:
                                    loader_safe = False
                            elif kw.arg == "Loader" and isinstance(kw.value, ast.Name):
                                if kw.value.id == "SafeLoader":
                                    loader_safe = True
                        if loader_safe:
                            return None

                    suggestion = {
                        "pickle": "Use json.loads() instead of pickle for LLM output.",
                        "cPickle": "Use json.loads() instead of pickle for LLM output.",
                        "marshal": "Use json.loads() instead of marshal for LLM output.",
                        "yaml": "Use yaml.safe_load() instead of yaml.load() with unsafe Loader.",
                        "shelve": "Avoid shelve with untrusted data. Use json or a database.",
                    }.get(module, "Avoid deserialization of untrusted data.")

                    return display, suggestion

        return None

    @staticmethod
    def _is_dynamic(node: ast.expr) -> bool:
        """Check if a node is dynamic (not a constant)."""
        if isinstance(node, ast.Constant):
            return False
        return True
