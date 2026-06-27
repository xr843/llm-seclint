"""LS009: Detect LLM/user output used as an outbound request URL (SSRF)."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# HTTP client modules whose request methods take a URL as the first argument.
_HTTP_MODULES = {"requests", "httpx"}
_HTTP_METHODS = {
    "get", "post", "put", "delete", "head", "patch", "options", "request",
}


class SsrfRule(Rule):
    """Detect untrusted (LLM/user) input used as an outbound request URL."""

    rule_id = "LS009"
    rule_name = "llm-to-ssrf"
    severity = Severity.HIGH
    # Taint-gated: SSRF is specifically about an *untrusted* URL, so report only
    # when the URL is taint-confirmed to carry LLM/user input (a merely dynamic
    # URL like requests.get(config_url) is not flagged).
    stability = "stable"
    description = (
        "LLM or user input is used as the URL of an outbound HTTP request, "
        "allowing server-side request forgery (SSRF)."
    )
    cwe_id = "CWE-918"
    owasp_llm = "LLM02: Insecure Output Handling"

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str], taint: object | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            sink = self._classify(node)
            if sink is None:
                continue

            url_arg = self._url_arg(node)
            if url_arg is None or isinstance(url_arg, ast.Constant):
                continue

            src = self._confirmed_taint([url_arg], taint)
            if not src:
                continue

            findings.append(
                self._make_finding(
                    file_path,
                    node.lineno,
                    f"{src.upper()} input used as request URL in {sink} "
                    f"— confirmed SSRF dataflow",
                    source_lines,
                    col=node.col_offset,
                    fix_suggestion=(
                        "Validate the URL against an allowlist of hosts/schemes "
                        "before requesting it; never pass LLM/user output directly "
                        "as a request URL."
                    ),
                    taint_source=src,
                )
            )

        return findings

    @staticmethod
    def _classify(node: ast.Call) -> str | None:
        """Return a display name if the call is an outbound HTTP request, else None."""
        func = node.func
        if isinstance(func, ast.Attribute):
            # requests.get(...) / httpx.post(...)
            if (
                isinstance(func.value, ast.Name)
                and func.value.id in _HTTP_MODULES
                and func.attr in _HTTP_METHODS
            ):
                return f"{func.value.id}.{func.attr}()"
            # urllib.request.urlopen(...) (or any *.urlopen)
            if func.attr == "urlopen":
                return "urlopen()"
        elif isinstance(func, ast.Name) and func.id == "urlopen":
            return "urlopen()"
        return None

    @staticmethod
    def _url_arg(node: ast.Call) -> ast.expr | None:
        """Return the URL argument: the first positional arg, or ``url=``."""
        if node.args:
            return node.args[0]
        for kw in node.keywords:
            if kw.arg == "url":
                return kw.value
        return None
