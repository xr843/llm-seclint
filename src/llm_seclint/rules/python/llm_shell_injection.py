"""LS004: Detect LLM output passed to shell execution functions."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.analyzers.taint import TaintContext
from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# Functions that execute shell commands
_DANGEROUS_CALLS: dict[str, set[str]] = {
    # module -> function names
    "subprocess": {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"},
    "os": {"system", "popen", "popen2", "popen3", "popen4"},
}

# Standalone dangerous function names (when imported directly)
_DANGEROUS_STANDALONE = {"system", "popen"}

# Programs that execute a following argument as code/commands, so a dynamic
# argument is command/code injection even in argv form without shell=True
# (e.g. ["bash", "-c", x], ["python", "-c", x], ["node", "-e", x]).
_CODE_INTERPRETERS = {
    # shells
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "busybox",
    "pwsh", "powershell",
    # language interpreters that take an inline-code flag (-c / -e / -r)
    "python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php",
}


# File path patterns indicating CLI/build/dev tooling (not production LLM code)
_CLI_BUILD_DIRS = ("/cli/", "/tools/", "/scripts/")
_CLI_BUILD_FILENAMES = ("setup.py", "setup.cfg", "conftest.py", "manage.py")


class LlmShellInjectionRule(Rule):
    """Detect LLM output passed to shell execution functions."""

    rule_id = "LS004"
    rule_name = "llm-to-shell-injection"
    severity = Severity.CRITICAL
    description = (
        "LLM output is passed to a shell execution function. "
        "This allows arbitrary command execution if the LLM is compromised."
    )
    cwe_id = "CWE-78"
    owasp_llm = "LLM02: Insecure Output Handling"

    @staticmethod
    def _is_cli_or_build_file(file_path: Path) -> bool:
        """Return True if the file is in a CLI/build/scripts directory or is a build file."""
        path_str = str(file_path)
        # Normalise to forward slashes for cross-platform matching
        path_posix = path_str.replace("\\", "/")
        if any(d in path_posix for d in _CLI_BUILD_DIRS):
            return True
        if file_path.name in _CLI_BUILD_FILENAMES:
            return True
        return False

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str], taint: object | None = None
    ) -> list[Finding]:
        # Skip CLI/build/dev tooling files entirely
        if self._is_cli_or_build_file(file_path):
            return []

        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_info = self._classify_call(node)
            if call_info is None:
                continue

            func_display, is_subprocess = call_info

            # For subprocess functions, also check for shell=True
            if is_subprocess:
                has_shell_true = any(
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and bool(kw.value.value)
                    for kw in node.keywords
                )

                if node.args:
                    cmd_arg = node.args[0]

                    if isinstance(cmd_arg, (ast.List, ast.Tuple)):
                        # argv form (list or tuple). Without shell=True the shell
                        # never parses the arguments, so shell injection is
                        # structurally impossible -- this is the OWASP/Python
                        # recommended mitigation (pair it with an allowlist to
                        # also bound which program runs). Only flag the misuse
                        # cases: shell=True combined with an argv list (Python
                        # joins it into a string for the shell), or an argv list
                        # that itself invokes a code interpreter with a dynamic
                        # argument, e.g. ["bash", "-c", user_input] or
                        # ["python", "-c", user_input].
                        should_flag = has_shell_true or self._argv_invokes_interpreter(
                            cmd_arg
                        )
                    else:
                        # Non-list first arg (a string or variable command):
                        # dangerous when dynamic, especially with shell=True.
                        should_flag = self._is_dynamic(cmd_arg)

                    if should_flag:
                        src = self._confirmed_source(cmd_arg, taint)
                        msg = f"Dynamic output passed to {func_display}"
                        if has_shell_true:
                            msg += " with shell=True"
                        if src:
                            msg += f" — confirmed {src.upper()}→sink dataflow"
                        findings.append(
                            self._make_finding(
                                file_path,
                                node.lineno,
                                msg,
                                source_lines,
                                col=node.col_offset,
                                fix_suggestion=(
                                    "Never pass LLM output directly to shell commands. "
                                    "Use an allowlist of permitted commands and validate input."
                                ),
                                taint_source=src,
                            )
                        )
            else:
                # os.system, os.popen - always dangerous with dynamic input
                if node.args:
                    cmd_arg = node.args[0]
                    if self._is_dynamic(cmd_arg):
                        src = self._confirmed_source(cmd_arg, taint)
                        msg = f"Dynamic output passed to {func_display}"
                        if src:
                            msg += f" — confirmed {src.upper()}→sink dataflow"
                        findings.append(
                            self._make_finding(
                                file_path,
                                node.lineno,
                                msg,
                                source_lines,
                                col=node.col_offset,
                                fix_suggestion=(
                                    "Never pass LLM output to os.system/os.popen. "
                                    "Use subprocess with an argument list and validate input."
                                ),
                                taint_source=src,
                            )
                        )

        return findings

    @staticmethod
    def _classify_call(node: ast.Call) -> tuple[str, bool] | None:
        """Classify a call as a dangerous shell function.

        Returns (display_name, is_subprocess) or None.
        """
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                if module in _DANGEROUS_CALLS and attr in _DANGEROUS_CALLS[module]:
                    return f"{module}.{attr}()", module == "subprocess"
        elif isinstance(node.func, ast.Name):
            if node.func.id in _DANGEROUS_STANDALONE:
                return f"{node.func.id}()", False
        return None

    @staticmethod
    def _confirmed_source(cmd_arg: ast.expr, taint: object | None) -> str:
        """Return the taint source of the command argument (or of any argv
        element for list/tuple forms), or '' when not taint-confirmed."""
        if not isinstance(taint, TaintContext):
            return ""
        candidates = (
            cmd_arg.elts
            if isinstance(cmd_arg, (ast.List, ast.Tuple))
            else [cmd_arg]
        )
        for node in candidates:
            confirmed = taint.is_tainted(node)
            if confirmed:
                return confirmed
        return ""

    @staticmethod
    def _argv_invokes_interpreter(node: ast.List | ast.Tuple) -> bool:
        """Return True for argv like ``["bash", "-c", user_input]`` or
        ``["python", "-c", user_input]`` (also through wrappers such as
        ``["env", "bash", "-c", user_input]``).

        When a code interpreter appears among the leading constant elements and a
        later element is dynamic, the call is command/code injection even without
        ``shell=True`` -- the interpreter parses the dynamic argument as code.
        Scanning all leading constants (not just argv[0]) covers wrapper prefixes
        like ``env``/``sudo``/``nice``.
        """
        seen_interpreter = False
        for el in node.elts:
            if isinstance(el, ast.Constant) and isinstance(el.value, str):
                program = el.value.rsplit("/", 1)[-1].lower()
                if program in _CODE_INTERPRETERS:
                    seen_interpreter = True
            elif not isinstance(el, ast.Constant):
                # A dynamic element after a known interpreter is the injected code.
                if seen_interpreter:
                    return True
        return False

    @staticmethod
    def _is_dynamic(node: ast.expr) -> bool:
        """Check if a node represents dynamic (non-constant) content."""
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.List):
            # A list of constants is fine (subprocess argument list)
            return any(not isinstance(el, ast.Constant) for el in node.elts)
        return True
