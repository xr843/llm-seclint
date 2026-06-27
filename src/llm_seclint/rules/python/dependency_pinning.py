"""LS010: Detect insecure (unpinned) LLM dependency version constraints.

Motivated by the litellm supply chain attack where ``dspy`` used
``litellm>=1.64.0`` without an upper bound and got compromised.

This rule scans dependency files (requirements*.txt, pyproject.toml,
setup.cfg) for LLM-related packages that use open-ended version
constraints (e.g. ``>=`` without a corresponding ``<`` upper bound).
"""

from __future__ import annotations

import re
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import TextRule

# LLM ecosystem packages that are high-value supply chain targets.
LLM_PACKAGES: frozenset[str] = frozenset({
    "litellm",
    "openai",
    "anthropic",
    "langchain",
    "langchain-core",
    "langchain-community",
    "llama-index",
    "transformers",
    "vllm",
    "cohere",
    "google-generativeai",
    "mistralai",
    "groq",
    "together",
    "fireworks-ai",
    "dspy",
    "guidance",
    "semantic-kernel",
    "autogen",
})

# Normalise package names: PEP 503 treats hyphens, underscores, and dots
# as equivalent, and comparison is case-insensitive.
_NORMALISE_RE = re.compile(r"[-_.]+")


def _normalise(name: str) -> str:
    return _NORMALISE_RE.sub("-", name.strip()).lower()


_NORMALISED_LLM_PACKAGES: frozenset[str] = frozenset(
    _normalise(p) for p in LLM_PACKAGES
)


def _is_llm_package(name: str) -> bool:
    return _normalise(name) in _NORMALISED_LLM_PACKAGES


def _has_upper_bound(version_spec: str) -> bool:
    """Return True if the version specifier contains an upper bound.

    Upper bounds are indicated by ``<``, ``<=``, ``==``, ``~=``, or ``!=``.
    We specifically check for ``<`` or ``<=`` or ``==`` or ``~=`` operators,
    or the presence of a comma with ``<`` (e.g. ``>=1.0,<2.0``).
    """
    # Exact pin always safe
    if "==" in version_spec:
        return True
    # Compatible release (~=1.0 implies >=1.0,<2.0)
    if "~=" in version_spec:
        return True
    # Explicit upper bound
    if "<" in version_spec:
        return True
    return False


# ---- requirements.txt parsing ----

# Matches: package_name (>=|>|~=|==|!=|<=|<) version [, ...]
_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9][\w.\-]*)\s*(\[.*?\])?\s*(.*?)(?:\s*#.*)?$"
)


def _check_requirements_txt(
    source: str, file_path: Path, rule: "UnpinnedLlmDependencyRule"
) -> list[Finding]:
    findings: list[Finding]  = []
    source_lines = source.splitlines()
    for lineno_0, raw_line in enumerate(source_lines):
        line = raw_line.strip()
        # Skip empty lines, comments, and option flags
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        m = _REQ_LINE_RE.match(line)
        if not m:
            continue

        pkg_name = m.group(1)
        version_spec = m.group(3).strip()

        if not _is_llm_package(pkg_name):
            continue

        # No version spec at all is also risky, but >=  without upper bound
        # is the specific pattern we target.
        if ">=" not in version_spec:
            continue

        if _has_upper_bound(version_spec):
            continue

        findings.append(
            rule._make_finding(
                file_path=file_path,
                line=lineno_0 + 1,
                message=(
                    f"LLM package '{pkg_name}' uses unpinned version "
                    f"constraint '{version_spec}'. This is vulnerable to "
                    f"supply chain attacks. Pin to an exact version or add "
                    f"an upper bound (e.g. '{pkg_name}>=x.y,<x.z')."
                ),
                source_lines=source_lines,
                fix_suggestion=(
                    f"Pin the version: {pkg_name}==<version> "
                    f"or add upper bound: {pkg_name}{version_spec},<NEXT_MAJOR"
                ),
            )
        )
    return findings


# ---- pyproject.toml parsing ----

# Match dependency strings like: "litellm>=1.64.0"
_PYPROJECT_DEP_RE = re.compile(
    r"""['"]([A-Za-z0-9][\w.\-]*)(?:\[.*?\])?\s*(>=\s*[\d][^'"]*?)['"]"""
)

# Match poetry-style: litellm = ">=1.64.0"  or litellm = {version = ">=1.64.0", ...}
_POETRY_DEP_RE = re.compile(
    r"""^([A-Za-z0-9][\w.\-]*)\s*=\s*(?:['"]|.*version\s*=\s*['"])(>=\s*[\d][^'"]*?)['"]""",
    re.MULTILINE,
)


def _in_dependencies_section(source_lines: list[str], lineno_0: int) -> bool:
    """Check if a line is within a dependency-related TOML context.

    This checks for:
    1. Direct dependency section headers like [project.dependencies] or
       [tool.poetry.dependencies]
    2. Lines inside a ``dependencies = [...]`` array within a [project] section
    3. Lines inside [project.optional-dependencies.*] sections
    """
    # Walk backwards to find context.
    for i in range(lineno_0, -1, -1):
        stripped = source_lines[i].strip()

        # Check if we're inside a dependencies = [...] array
        if "dependencies" in stripped.lower() and "=" in stripped and "[" in stripped:
            return True
        if stripped == "]":
            # We're below a closing bracket; check if above is deps array
            continue

        if stripped.startswith("["):
            lower = stripped.lower()
            if any(
                kw in lower
                for kw in (
                    "dependencies",
                    "requires",
                    "optional-dependencies",
                )
            ):
                return True
            # [project] section: deps could be in a `dependencies = [...]` key
            # We need to check if there's an open array above us
            if lower in ("[project]",):
                # Walk forward from section header to see if we're in deps array
                return _in_deps_array(source_lines, i, lineno_0)
            return False
    return False


def _in_deps_array(
    source_lines: list[str], section_start: int, target_line: int
) -> bool:
    """Check if target_line is inside a ``dependencies = [...]`` array."""
    in_deps = False
    bracket_depth = 0
    for i in range(section_start, min(target_line + 1, len(source_lines))):
        stripped = source_lines[i].strip()
        if stripped.startswith("[") and not in_deps:
            # New section header after our section = we've left the section
            if i > section_start and stripped.startswith("[") and not stripped.startswith("[["):
                # But only if it looks like a TOML section, not an array literal
                if "]" in stripped and "=" not in stripped:
                    return False

        lower = stripped.lower()
        if not in_deps:
            if "dependencies" in lower and "=" in stripped:
                in_deps = True
                bracket_depth += stripped.count("[") - stripped.count("]")
                if i == target_line:
                    return True
                continue
        else:
            bracket_depth += stripped.count("[") - stripped.count("]")
            if i == target_line:
                return bracket_depth > 0
            if bracket_depth <= 0:
                in_deps = False
    return False


def _check_pyproject_toml(
    source: str, file_path: Path, rule: "UnpinnedLlmDependencyRule"
) -> list[Finding]:
    findings: list[Finding] = []
    source_lines = source.splitlines()

    # Strategy: scan each line for LLM package references with >= constraints
    for lineno_0, raw_line in enumerate(source_lines):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Must be in a dependencies section
        if not _in_dependencies_section(source_lines, lineno_0):
            continue

        # Check PEP 621 style: "litellm>=1.64.0"
        for m in _PYPROJECT_DEP_RE.finditer(raw_line):
            pkg_name = m.group(1)
            version_spec = m.group(2).strip()
            if _is_llm_package(pkg_name) and not _has_upper_bound(version_spec):
                findings.append(
                    rule._make_finding(
                        file_path=file_path,
                        line=lineno_0 + 1,
                        message=(
                            f"LLM package '{pkg_name}' uses unpinned version "
                            f"constraint '{version_spec}' in pyproject.toml. "
                            f"Pin to an exact version or add an upper bound."
                        ),
                        source_lines=source_lines,
                        fix_suggestion=(
                            f"Pin the version: {pkg_name}==<version> "
                            f"or add upper bound: {pkg_name}{version_spec},<NEXT_MAJOR"
                        ),
                    )
                )

        # Check Poetry style: litellm = ">=1.64.0"
        for m in _POETRY_DEP_RE.finditer(raw_line):
            pkg_name = m.group(1)
            version_spec = m.group(2).strip()
            if _is_llm_package(pkg_name) and not _has_upper_bound(version_spec):
                # Avoid duplicate if already caught by PEP 621 pattern
                already_found = any(
                    f.line == lineno_0 + 1 and pkg_name in f.message
                    for f in findings
                )
                if not already_found:
                    findings.append(
                        rule._make_finding(
                            file_path=file_path,
                            line=lineno_0 + 1,
                            message=(
                                f"LLM package '{pkg_name}' uses unpinned version "
                                f"constraint '{version_spec}' in pyproject.toml. "
                                f"Pin to an exact version or add an upper bound."
                            ),
                            source_lines=source_lines,
                            fix_suggestion=(
                                f"Pin the version: {pkg_name}==<version> "
                                f"or add upper bound: {pkg_name}{version_spec},<NEXT_MAJOR"
                            ),
                        )
                    )

    return findings


# ---- setup.cfg parsing ----

_SETUP_CFG_DEP_RE = re.compile(
    r"^([A-Za-z0-9][\w.\-]*)(?:\[.*?\])?\s*(>=\s*[\d].*)$"
)


def _check_setup_cfg(
    source: str, file_path: Path, rule: "UnpinnedLlmDependencyRule"
) -> list[Finding]:
    findings: list[Finding] = []
    source_lines = source.splitlines()
    in_deps_section = False

    for lineno_0, raw_line in enumerate(source_lines):
        stripped = raw_line.strip()

        # Track section headers
        if stripped.startswith("["):
            lower = stripped.lower()
            in_deps_section = "install_requires" in lower or "options" in lower
            continue

        # In [options] section, look for install_requires key
        if stripped.lower().startswith("install_requires"):
            in_deps_section = True
            continue

        if not in_deps_section:
            continue

        # Continuation lines are indented
        if not raw_line[0:1].isspace() and not stripped.startswith(("install_requires",)):
            if "=" in stripped and not stripped.startswith(("#", ";")):
                in_deps_section = False
                continue

        m = _SETUP_CFG_DEP_RE.match(stripped)
        if not m:
            continue

        pkg_name = m.group(1)
        version_spec = m.group(2).strip()

        if not _is_llm_package(pkg_name):
            continue

        if _has_upper_bound(version_spec):
            continue

        findings.append(
            rule._make_finding(
                file_path=file_path,
                line=lineno_0 + 1,
                message=(
                    f"LLM package '{pkg_name}' uses unpinned version "
                    f"constraint '{version_spec}' in setup.cfg. "
                    f"Pin to an exact version or add an upper bound."
                ),
                source_lines=source_lines,
                fix_suggestion=(
                    f"Pin the version: {pkg_name}==<version> "
                    f"or add upper bound: {pkg_name}{version_spec},<NEXT_MAJOR"
                ),
            )
        )

    return findings


# Dependency file names this rule can handle.
DEPENDENCY_FILE_PATTERNS: frozenset[str] = frozenset({
    "requirements.txt",
    "pyproject.toml",
    "setup.cfg",
})


def is_dependency_file(file_path: Path) -> bool:
    """Return True if the file is a dependency file this rule can scan."""
    name = file_path.name
    if name in DEPENDENCY_FILE_PATTERNS:
        return True
    # Also match requirements-*.txt and requirements_*.txt
    if name.startswith("requirements") and name.endswith(".txt"):
        return True
    return False


class UnpinnedLlmDependencyRule(TextRule):
    """Detect LLM dependencies with unpinned version constraints.

    Open-ended version constraints like ``litellm>=1.64.0`` allow future
    malicious releases to be automatically installed, as happened in the
    litellm supply chain attack via the dspy package.
    """

    rule_id = "LS010"
    rule_name = "unpinned-llm-dependency"
    severity = Severity.HIGH
    description = (
        "LLM dependency uses unpinned version constraint, "
        "vulnerable to supply chain attacks"
    )
    cwe_id = "CWE-1357"
    owasp_llm = ""

    def check_text(self, source: str, file_path: Path) -> list[Finding]:
        """Analyze a dependency file for unpinned LLM packages."""
        name = file_path.name

        if name == "pyproject.toml":
            return _check_pyproject_toml(source, file_path, self)
        elif name == "setup.cfg":
            return _check_setup_cfg(source, file_path, self)
        elif name.startswith("requirements") and name.endswith(".txt"):
            return _check_requirements_txt(source, file_path, self)

        return []
