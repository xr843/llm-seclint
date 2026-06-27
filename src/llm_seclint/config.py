"""Configuration loading and validation."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_RULE_ID_PATTERN = re.compile(r"^LS\d{3}$")
_KNOWN_KEYS = {
    "include_patterns",
    "exclude_patterns",
    "ignore_rules",
    "min_severity",
    "output_format",
    "output_file",
    "include_experimental",
}

_MAX_TRAVERSAL_LEVELS = 5


class ScanConfig(BaseModel):
    """Configuration for a scan run."""

    include_patterns: list[str] = Field(default_factory=lambda: ["*.py"])
    exclude_patterns: list[str] = Field(default_factory=list)
    ignore_rules: list[str] = Field(default_factory=list)
    min_severity: str = "HIGH"
    output_format: str = "text"
    output_file: str = ""
    include_experimental: bool = False

    model_config = {"extra": "ignore"}


def _get_git_root() -> Path | None:
    """Return the git repository root, or None if not in a git repo."""
    try:
        result = subprocess.run(  # noqa: S603, S607
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except FileNotFoundError:
        pass
    return None


def _validate_config_data(data: dict[str, object]) -> None:
    """Validate config data and warn on issues.

    Raises SystemExit for invalid min_severity.
    Prints warnings to stderr for unknown keys and invalid rule IDs.
    """
    # Warn on unknown keys
    unknown_keys = set(data.keys()) - _KNOWN_KEYS
    for key in sorted(unknown_keys):
        print(f"Warning: unknown config key '{key}'", file=sys.stderr)

    # Validate min_severity
    severity = data.get("min_severity", "")
    if severity and severity not in _VALID_SEVERITIES:
        raise SystemExit(
            f"Error: invalid min_severity '{severity}'. "
            f"Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"
        )

    # Validate ignore_rules format
    rules = data.get("ignore_rules", [])
    if isinstance(rules, list):
        for rule_id in rules:
            if not _RULE_ID_PATTERN.match(str(rule_id)):
                print(
                    f"Warning: invalid rule ID '{rule_id}', expected format LS###",
                    file=sys.stderr,
                )


def load_config(config_path: Path | None = None) -> ScanConfig:
    """Load configuration from a YAML file.

    Searches for .llm-seclint.yml in the current directory and parent
    directories if no explicit path is given.

    Args:
        config_path: Explicit path to a config file, or None to auto-discover.

    Returns:
        Parsed and validated ScanConfig.
    """
    if config_path is not None:
        return _parse_config_file(config_path)

    # Auto-discover config file with traversal limit
    search_dir = Path.cwd()
    git_root = _get_git_root()

    levels_checked = 0
    for directory in [search_dir, *search_dir.parents]:
        if levels_checked >= _MAX_TRAVERSAL_LEVELS:
            break
        # Stop at git root (after checking it)
        at_git_root = git_root is not None and directory == git_root

        candidate = directory / ".llm-seclint.yml"
        if candidate.is_file():
            return _parse_config_file(candidate)
        candidate = directory / ".llm-seclint.yaml"
        if candidate.is_file():
            return _parse_config_file(candidate)

        if at_git_root:
            break
        levels_checked += 1

    return ScanConfig()


def _parse_config_file(path: Path) -> ScanConfig:
    """Parse a YAML config file into a ScanConfig."""
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except (OSError, yaml.YAMLError) as exc:
        raise SystemExit(f"Error reading config file {path}: {exc}") from exc

    if not isinstance(data, dict):
        return ScanConfig()

    _validate_config_data(data)

    return ScanConfig(**data)
