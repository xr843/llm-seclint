"""Rule registry for managing available security rules."""

from __future__ import annotations

from llm_seclint.rules.base import Rule, TextRule
from llm_seclint.rules.python.dependency_pinning import UnpinnedLlmDependencyRule
from llm_seclint.rules.python.hardcoded_keys import HardcodedApiKeyRule
from llm_seclint.rules.python.insecure_deserialization import (
    InsecureDeserializationRule,
)
from llm_seclint.rules.python.llm_path_traversal import LlmPathTraversalRule
from llm_seclint.rules.python.llm_shell_injection import LlmShellInjectionRule
from llm_seclint.rules.python.llm_sql_injection import LlmSqlInjectionRule
from llm_seclint.rules.python.prompt_injection import PromptConcatInjectionRule
from llm_seclint.rules.python.ssrf import SsrfRule
from llm_seclint.rules.python.ssti import SSTIRule
from llm_seclint.rules.python.xxe import XXERule


class RuleRegistry:
    """Registry that holds all available rules and manages enable/disable state."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}
        self._text_rules: dict[str, TextRule] = {}
        self.disabled_rules: set[str] = set()

    def register(self, rule: Rule) -> None:
        """Register a rule instance."""
        self._rules[rule.rule_id] = rule

    def register_text_rule(self, rule: TextRule) -> None:
        """Register a text-based rule instance."""
        self._text_rules[rule.rule_id] = rule

    def disable_rule(self, rule_id: str) -> None:
        """Disable a rule by ID."""
        self.disabled_rules.add(rule_id)

    def enable_rule(self, rule_id: str) -> None:
        """Enable a previously disabled rule."""
        self.disabled_rules.discard(rule_id)

    def get_enabled_rules(self) -> list[Rule]:
        """Return all enabled AST-based rules."""
        return [
            rule
            for rule_id, rule in self._rules.items()
            if rule_id not in self.disabled_rules
        ]

    def get_enabled_text_rules(self) -> list[TextRule]:
        """Return all enabled text-based rules."""
        return [
            rule
            for rule_id, rule in self._text_rules.items()
            if rule_id not in self.disabled_rules
        ]

    def get_all_rules(self) -> list[Rule]:
        """Return all registered rules regardless of enabled state."""
        return list(self._rules.values())

    def get_all_text_rules(self) -> list[TextRule]:
        """Return all registered text-based rules regardless of enabled state."""
        return list(self._text_rules.values())

    def load_default_rules(self) -> None:
        """Load all built-in rules."""
        defaults: list[Rule] = [
            HardcodedApiKeyRule(),
            PromptConcatInjectionRule(),
            LlmSqlInjectionRule(),
            LlmShellInjectionRule(),
            LlmPathTraversalRule(),
            InsecureDeserializationRule(),
            SSTIRule(),
            XXERule(),
            SsrfRule(),
        ]
        for rule in defaults:
            self.register(rule)

        text_defaults: list[TextRule] = [
            UnpinnedLlmDependencyRule(),
        ]
        for rule in text_defaults:
            self.register_text_rule(rule)
