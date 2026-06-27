"""LS009: Detect LLM/user output used as an outbound request URL (SSRF)."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# HTTP client modules whose request methods take a URL argument.
_HTTP_MODULES = {"requests", "httpx"}
_HTTP_METHODS = {
    "get", "post", "put", "delete", "head", "patch", "options", "request",
}
# (module, constructor) pairs that build a reusable HTTP session/client whose
# instance then exposes the same request methods.
_SESSION_CTORS = {
    ("requests", "Session"),
    ("httpx", "Client"),
    ("httpx", "AsyncClient"),
    ("aiohttp", "ClientSession"),
    ("urllib3", "PoolManager"),
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
        session_vars = self._session_vars(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            info = self._classify(node, session_vars)
            if info is None:
                continue
            display, method = info

            url_arg = self._url_arg(node, method)
            if url_arg is None or isinstance(url_arg, ast.Constant):
                continue

            src = self._confirmed_taint([url_arg], taint)
            if not src:
                continue

            findings.append(
                self._make_finding(
                    file_path,
                    node.lineno,
                    f"{src.upper()} input used as request URL in {display} "
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
    def _session_vars(tree: ast.Module) -> set[str]:
        """Collect variables assigned from an HTTP session/client constructor."""
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and SsrfRule._is_session_ctor(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        return names

    @staticmethod
    def _is_session_ctor(expr: ast.expr) -> bool:
        """True for ``requests.Session()`` / ``httpx.Client()`` / etc."""
        return (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and isinstance(expr.func.value, ast.Name)
            and (expr.func.value.id, expr.func.attr) in _SESSION_CTORS
        )

    @staticmethod
    def _classify(node: ast.Call, session_vars: set[str]) -> tuple[str, str] | None:
        """Return (display, method) if the call is an outbound HTTP request."""
        func = node.func
        if isinstance(func, ast.Attribute):
            method = func.attr
            recv = func.value
            # requests.get(...) / httpx.post(...)
            if (
                isinstance(recv, ast.Name)
                and recv.id in _HTTP_MODULES
                and method in _HTTP_METHODS
            ):
                return f"{recv.id}.{method}()", method
            # urllib.request.urlopen(...) (or any *.urlopen)
            if method == "urlopen":
                return "urlopen()", "urlopen"
            # session_var.get(...) where session_var = requests.Session() etc.
            if (
                method in _HTTP_METHODS
                and isinstance(recv, ast.Name)
                and recv.id in session_vars
            ):
                return f"{recv.id}.{method}()", method
            # inline: requests.Session().get(...)
            if method in _HTTP_METHODS and SsrfRule._is_session_ctor(recv):
                return f"session.{method}()", method
        elif isinstance(func, ast.Name) and func.id == "urlopen":
            return "urlopen()", "urlopen"
        return None

    @staticmethod
    def _url_arg(node: ast.Call, method: str) -> ast.expr | None:
        """Return the URL argument. ``request(method, url)`` takes the URL as the
        second positional arg; everything else takes it first. ``url=`` is honored."""
        idx = 1 if method == "request" else 0
        if len(node.args) > idx:
            return node.args[idx]
        for kw in node.keywords:
            if kw.arg == "url":
                return kw.value
        return None
