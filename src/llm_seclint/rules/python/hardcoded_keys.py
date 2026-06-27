"""LS001: Detect hardcoded API keys for LLM providers."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# Patterns that match known LLM provider API key prefixes
_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),          # OpenAI / DeepSeek
    re.compile(r"sk-proj-[a-zA-Z0-9_-]{20,}"),      # OpenAI project keys
    re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}"),       # Anthropic
    re.compile(r"anthropic_[a-zA-Z0-9_-]{20,}"),     # Anthropic legacy
    re.compile(r"xai-[a-zA-Z0-9_-]{20,}"),           # xAI / Grok
    re.compile(r"AIza[a-zA-Z0-9_-]{30,}"),           # Google AI
    re.compile(r"hf_[a-zA-Z0-9]{20,}"),              # Hugging Face
    re.compile(r"r8_[a-zA-Z0-9]{20,}"),              # Replicate
    re.compile(r"gsk_[a-zA-Z0-9]{20,}"),             # Groq
    re.compile(r"fw_[a-zA-Z0-9]{20,}"),              # Fireworks AI
    re.compile(r"co_[a-zA-Z0-9]{20,}"),              # Cohere v2
    re.compile(r"mistral-[a-zA-Z0-9]{20,}"),         # Mistral
]

# Variable names that suggest API key storage
_KEY_VAR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)"),
    re.compile(r"(?i)(openai|anthropic|cohere|hugging|replicate|mistral|groq|together|deepseek|fireworks).*key"),
]


class HardcodedApiKeyRule(Rule):
    """Detect hardcoded LLM provider API keys in source code."""

    rule_id = "LS001"
    rule_name = "hardcoded-api-key"
    severity = Severity.CRITICAL
    description = (
        "Hardcoded API keys for LLM providers detected. "
        "Use environment variables or a secrets manager instead."
    )
    cwe_id = "CWE-798"
    owasp_llm = "LLM06: Sensitive Information Disclosure"

    # Common non-key value substrings (lowercase comparison)
    _NON_KEY_WORDS: set[str] = {
        "header", "name", "prefix", "redis", "cookie", "format", "type",
        "suffix", "path", "field", "index", "label", "title",
    }

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str], taint: object | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            # Case 1: Simple name assignment like `api_key = "sk-..."` or `OPENAI_API_KEY = "sk-..."`
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        continue  # Handled by Case 3 below
                    target_name = self._get_name(target)
                    if target_name and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        value = node.value.value
                        if self._is_url(value):
                            continue
                        if self._is_key_value(value) or (
                            self._is_key_variable(target_name)
                            and len(value) > 8
                            and not value.startswith(("os.environ", "$", "{"))
                            and self._looks_like_real_key(value)
                        ):
                            findings.append(
                                self._make_finding(
                                    file_path,
                                    node.lineno,
                                    f"Hardcoded API key assigned to '{target_name}'",
                                    source_lines,
                                    col=node.col_offset,
                                    fix_suggestion=f'Use os.environ["{target_name}"] or a secrets manager',
                                )
                            )

            # Case 2: Keyword argument like `api_key="sk-..."`
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg
                        and self._is_key_variable(kw.arg)
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        value = kw.value.value
                        if self._is_url(value):
                            continue
                        if self._is_key_value(value) or (
                            len(value) > 8
                            and not value.startswith(("os.environ", "$", "{"))
                            and self._looks_like_real_key(value)
                        ):
                            findings.append(
                                self._make_finding(
                                    file_path,
                                    kw.value.lineno,
                                    f"Hardcoded API key passed as keyword argument '{kw.arg}'",
                                    source_lines,
                                    col=kw.value.col_offset,
                                    fix_suggestion=f'Use os.environ.get("{kw.arg.upper()}")',
                                )
                            )

            # Case 3: Attribute assignment like `openai.api_key = "sk-..."`
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if (
                    isinstance(target, ast.Attribute)
                    and self._is_key_variable(target.attr)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    value = node.value.value
                    if self._is_url(value):
                        continue
                    if self._is_key_value(value) or (
                        len(value) > 8
                        and not value.startswith(("os.environ", "$", "{"))
                        and self._looks_like_real_key(value)
                    ):
                        attr_str = self._get_name(target)
                        findings.append(
                            self._make_finding(
                                file_path,
                                node.lineno,
                                f"Hardcoded API key assigned to '{attr_str}'",
                                source_lines,
                                col=node.col_offset,
                                fix_suggestion="Use os.environ or a secrets manager",
                            )
                        )

        return findings

    @staticmethod
    def _is_url(value: str) -> bool:
        """Return True if the value is a URL, not an API key."""
        return value.startswith(("http://", "https://"))

    @staticmethod
    def _is_key_value(value: str) -> bool:
        """Check if a string value looks like an API key."""
        return any(pat.search(value) for pat in _KEY_PATTERNS)

    @staticmethod
    def _is_key_variable(name: str) -> bool:
        """Check if a variable name suggests it holds an API key."""
        return any(pat.search(name) for pat in _KEY_VAR_PATTERNS)

    @classmethod
    def _looks_like_real_key(cls, value: str) -> bool:
        """Return True only if *value* resembles a real API key.

        Filters out constant names (``REDIS_KEY_PREFIX``), short descriptive
        strings (``"header"``, ``"X-API-Key"``), and other values that are
        clearly not secret key material.
        """
        # Must be longer than 20 characters
        if len(value) <= 20:
            return False

        # Must contain both letters and digits
        has_alpha = any(c.isalpha() for c in value)
        has_digit = any(c.isdigit() for c in value)
        if not (has_alpha and has_digit):
            return False

        # All-uppercase values with underscores are constant names, not keys
        stripped = value.replace("_", "").replace("-", "")
        if stripped.isupper():
            return False

        # Contains a common non-key word → probably descriptive, not a secret
        lower = value.lower()
        if any(word in lower for word in cls._NON_KEY_WORDS):
            return False

        return True

    @staticmethod
    def _get_name(node: ast.expr) -> str:
        """Extract a human-readable name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = HardcodedApiKeyRule._get_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr
        return ""
