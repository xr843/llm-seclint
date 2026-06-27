"""Scan engine that orchestrates file discovery, analysis, and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
from llm_seclint.config import ScanConfig
from llm_seclint.core.file_discovery import discover_dependency_files, discover_files
from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.python.dependency_pinning import is_dependency_file
from llm_seclint.rules.registry import RuleRegistry


@dataclass
class SkippedFile:
    """A file that was skipped during scanning."""

    path: Path
    reason: str


@dataclass
class ScanResult:
    """Result of a scan run."""

    findings: list[Finding] = field(default_factory=list)
    scanned_count: int = 0
    skipped_files: list[SkippedFile] = field(default_factory=list)


class ScanEngine:
    """Main scan engine that coordinates the analysis pipeline."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.registry = RuleRegistry()
        self.registry.load_default_rules()
        self._apply_config()

    def _apply_config(self) -> None:
        """Apply configuration to filter rules."""
        # Experimental (heuristic, higher false-positive) rules are off unless
        # explicitly enabled, so the default scan is high-precision.
        if not self.config.include_experimental:
            for rule in self.registry.get_all_rules():
                if rule.stability == "experimental":
                    self.registry.disable_rule(rule.rule_id)
            for text_rule in self.registry.get_all_text_rules():
                if text_rule.stability == "experimental":
                    self.registry.disable_rule(text_rule.rule_id)

        if self.config.ignore_rules:
            for rule_id in self.config.ignore_rules:
                self.registry.disable_rule(rule_id)

        if self.config.min_severity:
            severity_order = list(Severity)
            try:
                min_idx = severity_order.index(Severity(self.config.min_severity))
            except ValueError:
                return
            allowed = set(severity_order[: min_idx + 1])
            for rule in list(self.registry.get_enabled_rules()):
                if rule.severity not in allowed:
                    self.registry.disable_rule(rule.rule_id)
            for text_rule in list(self.registry.get_enabled_text_rules()):
                if text_rule.severity not in allowed:
                    self.registry.disable_rule(text_rule.rule_id)

    def scan(self, paths: list[Path]) -> ScanResult:
        """Scan the given paths and return all findings.

        Args:
            paths: Files or directories to scan.

        Returns:
            ScanResult containing findings, scanned file count, and skipped files.
        """
        files = discover_files(
            paths,
            include_patterns=self.config.include_patterns or None,
            exclude_patterns=self.config.exclude_patterns or None,
        )

        result = ScanResult()

        enabled_rules = self.registry.get_enabled_rules()
        if not enabled_rules:
            return result

        analyzer = PythonAnalyzer(rules=enabled_rules)

        for file_path in files:
            try:
                source = file_path.read_text(encoding="utf-8")
            except OSError as exc:
                result.skipped_files.append(
                    SkippedFile(path=file_path, reason=f"read error: {exc}")
                )
                continue
            except UnicodeDecodeError as exc:
                result.skipped_files.append(
                    SkippedFile(path=file_path, reason=f"encoding error: {exc}")
                )
                continue

            file_findings, parse_error = analyzer.analyze(source, file_path)
            if parse_error:
                result.skipped_files.append(
                    SkippedFile(path=file_path, reason=parse_error)
                )
            result.findings.extend(file_findings)
            result.scanned_count += 1

        # Scan dependency files with text-based rules
        text_rules = self.registry.get_enabled_text_rules()
        if text_rules:
            dep_files = discover_dependency_files(paths)
            for dep_path in dep_files:
                try:
                    source = dep_path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    result.skipped_files.append(
                        SkippedFile(path=dep_path, reason=f"read error: {exc}")
                    )
                    continue
                for text_rule in text_rules:
                    if is_dependency_file(dep_path):
                        rule_findings = text_rule.check_text(source, dep_path)
                        result.findings.extend(rule_findings)
                result.scanned_count += 1

        result.findings = self._deduplicate(result.findings)
        result.findings.sort(key=lambda f: (str(f.file_path), f.line))
        return result

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings with the same rule_id, file_path, and line."""
        seen: set[tuple[str, str, int]] = set()
        result: list[Finding] = []
        for f in findings:
            key = (f.rule_id, str(f.file_path), f.line)
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result

    def get_rules_info(self) -> list[dict[str, str]]:
        """Return information about all registered rules."""
        all_rules = [
            {
                "id": rule.rule_id,
                "name": rule.rule_name,
                "severity": str(rule.severity),
                "description": rule.description,
                "cwe_id": rule.cwe_id,
                "stability": rule.stability,
                "enabled": str(rule.rule_id not in self.registry.disabled_rules),
            }
            for rule in self.registry.get_all_rules()
        ]
        all_rules.extend(
            {
                "id": rule.rule_id,
                "name": rule.rule_name,
                "severity": str(rule.severity),
                "description": rule.description,
                "cwe_id": rule.cwe_id,
                "stability": rule.stability,
                "enabled": str(rule.rule_id not in self.registry.disabled_rules),
            }
            for rule in self.registry.get_all_text_rules()
        )
        return all_rules
