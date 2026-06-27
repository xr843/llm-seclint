"""Finding dataclass representing a detected security issue."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from llm_seclint.core.severity import Severity


@dataclass(frozen=True)
class Finding:
    """A single security finding detected by a rule."""

    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    file_path: Path
    line: int
    col: int = 0
    end_line: int | None = None
    code_snippet: str = ""
    fix_suggestion: str = ""
    cwe_id: str = ""
    owasp_llm: str = ""
    taint_source: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize finding to a dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": str(self.severity),
            "message": self.message,
            "file": str(self.file_path),
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "cwe_id": self.cwe_id,
            "owasp_llm": self.owasp_llm,
            "taint_source": self.taint_source,
        }
