"""LS008: Detect XML External Entity (XXE) injection vulnerabilities."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# Dangerous XML parsing patterns: module -> {function names}
_DANGEROUS_XML_FUNCS: dict[str, set[str]] = {
    "etree": {"parse", "fromstring"},
    "ElementTree": {"parse", "fromstring"},
    "minidom": {"parse", "parseString"},
    "sax": {"parse", "parseString"},
}

# Module path segments that indicate stdlib xml usage
_STDLIB_XML_MODULES = {"xml", "lxml"}

# Safe alternative module
_SAFE_MODULE = "defusedxml"


class XXERule(Rule):
    """Detect unsafe XML parsing vulnerable to XXE attacks."""

    rule_id = "LS008"
    rule_name = "xxe-xml-parsing"
    severity = Severity.HIGH
    description = (
        "XML parsing without protection against external entity attacks"
    )
    cwe_id = "CWE-611"
    owasp_llm = "A05:2021: Security Misconfiguration"

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
            message = f"Unsafe XML parsing via {func_display}"
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
        """Classify a call as dangerous XML parsing. Returns (display, suggestion) or None."""
        func = node.func

        if not isinstance(func, ast.Attribute):
            return None

        attr = func.attr
        value = func.value

        # Check for defusedxml usage anywhere in the chain — always safe
        if XXERule._has_defusedxml(func):
            return None

        # module.func() — e.g., etree.parse(), minidom.parseString()
        if isinstance(value, ast.Name):
            module = value.id
            if module in _DANGEROUS_XML_FUNCS and attr in _DANGEROUS_XML_FUNCS[module]:
                display = f"{module}.{attr}()"
                return (
                    display,
                    f"Use defusedxml instead of {module}.{attr}(). "
                    f"Install defusedxml and replace with defusedxml equivalents.",
                )

        # Chained access: xml.etree.ElementTree.parse(), xml.sax.parse(), etc.
        if isinstance(value, ast.Attribute):
            parent_attr = value.attr
            if parent_attr in _DANGEROUS_XML_FUNCS and attr in _DANGEROUS_XML_FUNCS[parent_attr]:
                full_name = XXERule._reconstruct_dotted(func)
                return (
                    f"{full_name}()",
                    "Use defusedxml instead. "
                    "Install defusedxml and replace with defusedxml equivalents.",
                )

        return None

    @staticmethod
    def _has_defusedxml(node: ast.expr) -> bool:
        """Check if any part of the attribute chain contains 'defusedxml'."""
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            if current.attr == _SAFE_MODULE:
                return True
            current = current.value
        if isinstance(current, ast.Name) and current.id == _SAFE_MODULE:
            return True
        return False

    @staticmethod
    def _reconstruct_dotted(node: ast.expr) -> str:
        """Reconstruct a dotted name from an attribute chain."""
        parts: list[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _is_dynamic(node: ast.expr) -> bool:
        """Check if a node is dynamic (not a constant)."""
        if isinstance(node, ast.Constant):
            return False
        return True
