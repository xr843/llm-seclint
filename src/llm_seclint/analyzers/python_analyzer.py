"""Python AST-based analyzer."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from llm_seclint.analyzers.base import BaseAnalyzer
from llm_seclint.analyzers.taint import TaintContext
from llm_seclint.core.finding import Finding
from llm_seclint.rules.base import Rule

# Matches "nosec" optionally followed by whitespace and comma-separated rule IDs
_NOSEC_RE = re.compile(r"nosec(?:\s+([A-Z0-9]+(?:\s*,\s*[A-Z0-9]+)*))?")


def _is_suppressed(finding: Finding, source_lines: list[str]) -> bool:
    """Return True if the finding's source line contains a matching ``# nosec`` comment."""
    line_idx = finding.line - 1
    if line_idx < 0 or line_idx >= len(source_lines):
        return False

    line = source_lines[line_idx]

    # Only look in the comment portion of the line
    comment_start = line.find("#")
    if comment_start == -1:
        return False

    comment = line[comment_start:]
    match = _NOSEC_RE.search(comment)
    if match is None:
        return False

    # If no specific rule IDs given → suppress all rules
    rule_ids_str = match.group(1)
    if rule_ids_str is None:
        return True

    # Parse comma-separated rule IDs and check for a match
    suppressed_ids = {rid.strip() for rid in rule_ids_str.split(",")}
    return finding.rule_id in suppressed_ids


class PythonAnalyzer(BaseAnalyzer):
    """Analyzer that parses Python source into an AST and runs rules against it."""

    def __init__(self, rules: list[Rule]) -> None:
        super().__init__(rules)

    def analyze(
        self, source: str, file_path: Path
    ) -> tuple[list[Finding], str | None]:
        """Parse Python source and run all rules against the AST.

        Args:
            source: Python source code.
            file_path: Path to the source file.

        Returns:
            Tuple of (findings list, parse_error string or None).
        """
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as exc:
            lineno = exc.lineno or 0
            return [], f"SyntaxError at line {lineno}"

        # Build taint context. Taint must never break a scan, so any failure
        # degrades safely to an empty context (rules fall back to current behavior).
        try:
            taint = TaintContext.from_module(tree)
        except Exception:  # noqa: BLE001 - defensive: taint is best-effort
            taint = TaintContext({})

        source_lines = source.splitlines()
        findings: list[Finding] = []

        for rule in self.rules:
            rule_findings = rule.check(tree, file_path, source_lines, taint=taint)
            findings.extend(rule_findings)

        # Filter out findings suppressed by inline # nosec comments
        findings = [f for f in findings if not _is_suppressed(f, source_lines)]

        return findings, None
