"""CLI interface for llm-seclint."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.text import Text

from llm_seclint import __version__
from llm_seclint.config import load_config
from llm_seclint.core.engine import ScanEngine
from llm_seclint.formatters.json_fmt import JsonFormatter
from llm_seclint.formatters.sarif import SarifFormatter
from llm_seclint.formatters.text import TextFormatter

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


@click.group()
@click.version_option(version=__version__, prog_name="llm-seclint")
def main() -> None:
    """llm-seclint: Static security linter for LLM-powered applications."""


@main.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "sarif"]),
    default=None,
    help="Output format.",
)
@click.option(
    "-o",
    "--output",
    "output_file",
    type=click.Path(),
    default=None,
    help="Write output to a file.",
)
@click.option(
    "--ignore",
    "ignore_rules",
    default=None,
    help="Comma-separated list of rule IDs to ignore (e.g., LS001,LS002).",
)
@click.option(
    "--include",
    "include_patterns",
    default=None,
    help='Glob pattern for files to include (e.g., "*.py").',
)
@click.option(
    "--exclude",
    "exclude_patterns",
    default=None,
    help='Glob pattern for files to exclude (e.g., "test_*.py").',
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    default=None,
    help="Minimum severity to report (default: HIGH).",
)
@click.option(
    "--profile",
    type=click.Choice(["app", "engine"]),
    default="app",
    help="Scan profile: 'app' (default) for LLM-powered apps, 'engine' for LLM inference engines.",
)
@click.option(
    "--experimental",
    is_flag=True,
    default=False,
    help="Also run experimental (heuristic, higher false-positive) rules, e.g. LS002/LS003.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Print detailed scan progress to stderr.",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    default=False,
    help="Only print findings, no summary. Useful for piping.",
)
@click.option(
    "--group/--no-group",
    "show_groups",
    default=True,
    help="Show/hide grouped summary of similar findings (text format only).",
)
def scan(
    paths: tuple[str, ...],
    output_format: str | None,
    output_file: str | None,
    ignore_rules: str | None,
    include_patterns: str | None,
    exclude_patterns: str | None,
    config_path: str | None,
    min_severity: str | None,
    profile: str,
    experimental: bool,
    verbose: bool,
    quiet: bool,
    show_groups: bool,
) -> None:
    """Scan files or directories for LLM security vulnerabilities.

    Exit codes:

    \b
      0  No findings
      1  Findings found
    """
    # Load config
    config = load_config(Path(config_path) if config_path else None)

    # Apply profile presets before CLI overrides
    if profile == "engine":
        config.ignore_rules = list(set(config.ignore_rules) | {"LS002"})

    # CLI overrides
    if output_format is not None:
        config.output_format = output_format
    if ignore_rules:
        config.ignore_rules = list(set(config.ignore_rules) | set(ignore_rules.split(",")))
    if include_patterns:
        config.include_patterns = [include_patterns]
    if exclude_patterns:
        config.exclude_patterns = list(
            set(config.exclude_patterns) | set(exclude_patterns.split(","))
        )
    if min_severity:
        config.min_severity = min_severity
    if experimental:
        config.include_experimental = True

    engine = ScanEngine(config)

    start = time.monotonic()
    target_paths = [Path(p) for p in paths]

    if verbose:
        click.echo(f"Scanning {len(target_paths)} path(s)...", err=True)

    scan_result = engine.scan(target_paths)
    elapsed = time.monotonic() - start
    findings = scan_result.findings

    if verbose:
        for skipped in scan_result.skipped_files:
            click.echo(f"Skipping {skipped.path}: {skipped.reason}", err=True)
        click.echo(
            f"Scanned {scan_result.scanned_count} file(s) in {elapsed:.2f}s",
            err=True,
        )

    # Format output
    if config.output_format == "json":
        formatter = JsonFormatter()
    elif config.output_format == "sarif":
        formatter = SarifFormatter()  # type: ignore[assignment]
    else:
        formatter = TextFormatter(  # type: ignore[assignment]
            use_color=not output_file,
            quiet=quiet,
            show_groups=show_groups,
        )

    result = formatter.format(findings, elapsed, file_count=scan_result.scanned_count)

    if output_file:
        Path(output_file).write_text(result, encoding="utf-8")
        click.echo(f"Results written to {output_file}")
    else:
        click.echo(result, nl=False)

    # Exit with non-zero if findings found
    if findings:
        sys.exit(1)


@main.command()
def rules() -> None:
    """List all available security rules."""
    engine = ScanEngine()
    rules_info = engine.get_rules_info()

    console = Console(stderr=False)

    console.print()
    header = Text()
    header.append(f"{'ID':<8} ", style="bold")
    header.append(f"{'CWE':<10} ", style="bold")
    header.append(f"{'Name':<30} ", style="bold")
    header.append(f"{'Severity':<10} ", style="bold")
    header.append(f"{'Stability':<13} ", style="bold")
    header.append("Description", style="bold")
    console.print(header)
    console.print("-" * 110)

    for rule in rules_info:
        line = Text()
        line.append(f"{rule['id']:<8} ")
        cwe = rule.get("cwe_id", "") or ""
        line.append(f"{cwe:<10} ")
        line.append(f"{rule['name']:<30} ")

        severity_color = _SEVERITY_COLORS.get(rule["severity"], "white")
        line.append(f"{rule['severity']:<10} ", style=severity_color)

        stability = rule.get("stability", "stable") or "stable"
        stability_color = "dim" if stability == "experimental" else "green"
        line.append(f"{stability:<13} ", style=stability_color)

        line.append(rule["description"])
        console.print(line)

    n_experimental = sum(
        1 for r in rules_info if r.get("stability") == "experimental"
    )
    console.print()
    console.print(
        f"[dim]{len(rules_info)} rule(s) available "
        f"({n_experimental} experimental, off unless --experimental)[/dim]"
    )
    console.print()
