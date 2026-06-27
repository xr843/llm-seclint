"""Abstract base class for analyzers."""

from __future__ import annotations

import abc
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.rules.base import Rule


class BaseAnalyzer(abc.ABC):
    """Abstract analyzer that processes source files using rules."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @abc.abstractmethod
    def analyze(
        self, source: str, file_path: Path
    ) -> tuple[list[Finding], str | None]:
        """Analyze a source file and return findings.

        Args:
            source: The source code content.
            file_path: Path to the source file.

        Returns:
            A tuple of (findings in the file, parse-error string or None).
        """
        ...
