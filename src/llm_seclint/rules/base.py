"""Abstract base class for security rules."""

from __future__ import annotations

import abc
import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity


class Rule(abc.ABC):
    """Abstract base class for a security detection rule."""

    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    cwe_id: str = ""
    owasp_llm: str = ""
    # "stable": low false-positive, sink-driven or pattern-unique -> on by default.
    # "experimental": relies on naming/keyword heuristics to guess the data
    # source (LLM/user), so higher false-positive rate -> off unless --experimental.
    stability: str = "stable"

    @abc.abstractmethod
    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str], taint: object | None = None
    ) -> list[Finding]:
        """Run the rule against an AST and return any findings.

        Args:
            tree: The parsed Python AST.
            file_path: Path to the source file.
            source_lines: Source code split into lines.

        Returns:
            List of findings detected by this rule.
        """
        ...

    def _make_finding(
        self,
        file_path: Path,
        line: int,
        message: str,
        source_lines: list[str],
        col: int = 0,
        fix_suggestion: str = "",
        taint_source: str = "",
    ) -> Finding:
        """Helper to create a Finding with common fields pre-filled."""
        snippet = ""
        if 0 < line <= len(source_lines):
            snippet = source_lines[line - 1].rstrip()

        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            message=message,
            file_path=file_path,
            line=line,
            col=col,
            code_snippet=snippet,
            fix_suggestion=fix_suggestion,
            cwe_id=self.cwe_id,
            owasp_llm=self.owasp_llm,
            taint_source=taint_source,
        )


class TextRule(abc.ABC):
    """Abstract base class for text-based (non-AST) security rules.

    Used for rules that analyze configuration and dependency files
    rather than Python source code ASTs.
    """

    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    cwe_id: str = ""
    owasp_llm: str = ""
    # "stable": low false-positive, sink-driven or pattern-unique -> on by default.
    # "experimental": relies on naming/keyword heuristics to guess the data
    # source (LLM/user), so higher false-positive rate -> off unless --experimental.
    stability: str = "stable"

    @abc.abstractmethod
    def check_text(
        self, source: str, file_path: Path
    ) -> list[Finding]:
        """Run the rule against file text content and return any findings.

        Args:
            source: The raw file content as a string.
            file_path: Path to the source file.

        Returns:
            List of findings detected by this rule.
        """
        ...

    def _make_finding(
        self,
        file_path: Path,
        line: int,
        message: str,
        source_lines: list[str],
        col: int = 0,
        fix_suggestion: str = "",
        taint_source: str = "",
    ) -> Finding:
        """Helper to create a Finding with common fields pre-filled."""
        snippet = ""
        if 0 < line <= len(source_lines):
            snippet = source_lines[line - 1].rstrip()

        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            message=message,
            file_path=file_path,
            line=line,
            col=col,
            code_snippet=snippet,
            fix_suggestion=fix_suggestion,
            cwe_id=self.cwe_id,
            owasp_llm=self.owasp_llm,
            taint_source=taint_source,
        )
