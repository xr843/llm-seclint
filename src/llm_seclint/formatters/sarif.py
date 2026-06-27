"""SARIF v2.1.0 output formatter for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from typing import Any

from llm_seclint import __version__
from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.formatters.base import BaseFormatter

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"


class SarifFormatter(BaseFormatter):
    """Format findings as SARIF v2.1.0 JSON for GitHub Code Scanning."""

    def format(
        self,
        findings: list[Finding],
        elapsed: float,
        file_count: int = 0,
    ) -> str:
        rules_map: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for finding in findings:
            # Build rule entry if not already seen
            if finding.rule_id not in rules_map:
                rule: dict[str, Any] = {
                    "id": finding.rule_id,
                    "name": finding.rule_name,
                    "shortDescription": {
                        "text": finding.rule_name,
                    },
                }
                help_uri = _build_help_uri(finding)
                if help_uri:
                    rule["helpUri"] = help_uri
                rules_map[finding.rule_id] = rule

            # Build result entry
            level = _SEVERITY_TO_LEVEL.get(finding.severity, "note")
            result: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": level,
                "message": {
                    "text": finding.message,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(finding.file_path),
                            },
                            "region": _build_region(finding),
                        }
                    }
                ],
            }
            results.append(result)

        # Deterministic rule ordering
        rules_list = [rules_map[rid] for rid in sorted(rules_map)]

        sarif: dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "llm-seclint",
                            "version": __version__,
                            "rules": rules_list,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2) + "\n"


def _build_region(finding: Finding) -> dict[str, int]:
    """Build a SARIF region object from a finding."""
    region: dict[str, int] = {
        "startLine": finding.line,
    }
    if finding.col:
        region["startColumn"] = finding.col
    if finding.end_line is not None:
        region["endLine"] = finding.end_line
    return region


def _build_help_uri(finding: Finding) -> str:
    """Build a help URI from CWE or OWASP references."""
    if finding.cwe_id:
        # e.g. "CWE-89" -> https://cwe.mitre.org/data/definitions/89.html
        num = finding.cwe_id.replace("CWE-", "")
        return f"https://cwe.mitre.org/data/definitions/{num}.html"
    if finding.owasp_llm:
        return "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
    return ""
