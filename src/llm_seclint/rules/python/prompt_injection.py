"""LS002: Detect user input concatenated into LLM prompts."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# Keywords that suggest a string is a prompt
_PROMPT_KEYWORDS = {
    "prompt",
    "system_prompt",
    "user_prompt",
    "system_message",
    "instruction",
    "template",
    "messages",
}

# LLM API call patterns (module.function or just function)
_LLM_CALL_ATTRS = {
    "create",
    "complete",
    "completions",
    "completion",
    "acompletion",
    "chat",
    "generate",
    "invoke",
}

# Phrases in static text that indicate a prompt context.
# These must be specific enough to avoid false positives on generic code.
_PROMPT_TEXT_KEYWORDS = (
    "you are",
    "as a ",
    "as an ",
    "your role",
    "your task",
    "your job",
    "respond as",
    "answer as",
    "system prompt",
    "system message",
    "instructions:",
    "context:",
    "user says",
    "user asks",
    "user input",
    "user message",
    "user query",
)

# Phrases for _is_prompt_string (used in BinOp / format checks).
# Must be prompt-specific to avoid false positives on generic strings.
_PROMPT_STRING_KEYWORDS = (
    "you are",
    "as a ",
    "as an ",
    "your role",
    "your task",
    "your job",
    "respond as",
    "answer as",
    "system prompt",
    "system message",
    "instructions:",
    "context:",
    "user says",
    "user asks",
    "user input",
    "user message",
    "user query",
)

# LangChain template class names
_LANGCHAIN_TEMPLATE_CLASSES = {
    "PromptTemplate",
    "ChatPromptTemplate",
    "HumanMessagePromptTemplate",
}


class PromptConcatInjectionRule(Rule):
    """Detect user input concatenated into prompt strings."""

    rule_id = "LS002"
    rule_name = "prompt-concat-injection"
    severity = Severity.HIGH
    # Heuristic: infers "prompt" + "user input" from string content / variable
    # names, so it over-reports. Off by default; enable with --experimental.
    stability = "experimental"
    description = (
        "User-controlled input is concatenated directly into an LLM prompt. "
        "This may allow prompt injection attacks."
    )
    cwe_id = "CWE-77"
    owasp_llm = "LLM01: Prompt Injection"

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        visitor = _PromptInjectionVisitor(self, file_path, source_lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings


class _PromptInjectionVisitor(ast.NodeVisitor):
    """AST visitor that detects prompt injection patterns."""

    def __init__(
        self, rule: PromptConcatInjectionRule, file_path: Path, source_lines: list[str]
    ) -> None:
        self.rule = rule
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: list[Finding] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignments to continue traversal into child nodes."""
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Check f-strings for prompt injection patterns.

        An f-string is suspicious if it contains both static text with
        prompt-like keywords AND dynamic (variable) values.
        """
        has_static_prompt_keyword = False
        has_dynamic_value = False

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                text_lower = value.value.lower()
                if any(kw in text_lower for kw in _PROMPT_TEXT_KEYWORDS):
                    has_static_prompt_keyword = True
            elif isinstance(value, ast.FormattedValue):
                has_dynamic_value = True

        if has_static_prompt_keyword and has_dynamic_value:
            self.findings.append(
                self.rule._make_finding(
                    self.file_path,
                    node.lineno,
                    "User input interpolated into prompt via f-string",
                    self.source_lines,
                    col=node.col_offset,
                    fix_suggestion=(
                        "Separate system prompts from user input. "
                        "Pass user input as a distinct message role."
                    ),
                )
            )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Check string concatenation with + operator and % formatting."""
        if isinstance(node.op, ast.Add):
            # Skip numeric arithmetic: prompt_tokens + completion_tokens, etc.
            if self._is_numeric_arithmetic(node.left, node.right):
                self.generic_visit(node)
                return

            # Check if left side is a prompt-like string
            if self._is_prompt_string(node.left) and self._is_variable(node.right):
                self.findings.append(
                    self.rule._make_finding(
                        self.file_path,
                        node.lineno,
                        "User input concatenated into prompt via + operator",
                        self.source_lines,
                        col=node.col_offset,
                        fix_suggestion="Use separate message roles instead of string concatenation.",
                    )
                )
            elif self._is_variable(node.left) and self._is_prompt_string(node.right):
                self.findings.append(
                    self.rule._make_finding(
                        self.file_path,
                        node.lineno,
                        "User input concatenated into prompt via + operator",
                        self.source_lines,
                        col=node.col_offset,
                        fix_suggestion="Use separate message roles instead of string concatenation.",
                    )
                )
        elif isinstance(node.op, ast.Mod):
            # Check % formatting: "You are a bot. User says: %s" % user_input
            if self._is_prompt_string(node.left) and self._is_variable(node.right):
                self.findings.append(
                    self.rule._make_finding(
                        self.file_path,
                        node.lineno,
                        "User input injected into prompt via % formatting",
                        self.source_lines,
                        col=node.col_offset,
                        fix_suggestion="Use separate message roles instead of % string formatting.",
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check .format() calls, LangChain templates, and LiteLLM calls."""
        # --- Existing: .format() on prompt strings ---
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and self._is_prompt_string(node.func.value)
        ):
            self.findings.append(
                self.rule._make_finding(
                    self.file_path,
                    node.lineno,
                    "User input injected into prompt via .format()",
                    self.source_lines,
                    col=node.col_offset,
                    fix_suggestion="Use separate message roles instead of string formatting.",
                )
            )

        # --- LangChain: PromptTemplate(template=f"...{var}...") ---
        self._check_langchain_prompt_template(node)

        # --- LangChain: ChatPromptTemplate.from_messages(...) ---
        self._check_langchain_chat_prompt_template(node)

        # --- LangChain: HumanMessagePromptTemplate.from_template(var) ---
        self._check_langchain_human_message_template(node)

        # --- LiteLLM: litellm.completion / acompletion with dynamic system msg ---
        self._check_litellm_completion(node)

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # LangChain detection helpers
    # ------------------------------------------------------------------

    def _check_langchain_prompt_template(self, node: ast.Call) -> None:
        """Detect PromptTemplate(template=f"...{var}...") or template="..." + var."""
        func_name = self._get_call_name(node)
        if func_name != "PromptTemplate":
            return

        template_arg = self._get_keyword_arg(node, "template")
        if template_arg is None and node.args:
            template_arg = node.args[0]

        if template_arg is None:
            return

        if self._is_dynamic_string(template_arg):
            self.findings.append(
                self.rule._make_finding(
                    self.file_path,
                    node.lineno,
                    "Dynamic content in LangChain PromptTemplate — potential prompt injection",
                    self.source_lines,
                    col=node.col_offset,
                    fix_suggestion=(
                        "Use LangChain template placeholders like {topic} instead of "
                        "f-strings or concatenation in PromptTemplate."
                    ),
                )
            )

    def _check_langchain_chat_prompt_template(self, node: ast.Call) -> None:
        """Detect ChatPromptTemplate.from_messages with dynamic system message."""
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "from_messages"
        ):
            return

        # Check if the object is ChatPromptTemplate
        func_value = node.func.value
        obj_name = None
        if isinstance(func_value, ast.Name):
            obj_name = func_value.id
        elif isinstance(func_value, ast.Attribute):
            obj_name = func_value.attr

        if obj_name != "ChatPromptTemplate":
            return

        # First positional arg should be a list of message tuples
        if not node.args:
            return

        messages_arg = node.args[0]
        if not isinstance(messages_arg, ast.List):
            return

        for elt in messages_arg.elts:
            if not isinstance(elt, ast.Tuple) or len(elt.elts) < 2:
                continue
            role_node = elt.elts[0]
            content_node = elt.elts[1]

            # Check if role is "system"
            if (
                isinstance(role_node, ast.Constant)
                and isinstance(role_node.value, str)
                and role_node.value.lower() == "system"
                and self._is_dynamic_string(content_node)
            ):
                self.findings.append(
                    self.rule._make_finding(
                        self.file_path,
                        node.lineno,
                        "Dynamic content in LangChain ChatPromptTemplate system message — potential prompt injection",
                        self.source_lines,
                        col=node.col_offset,
                        fix_suggestion=(
                            "Use LangChain template placeholders instead of "
                            "f-strings in system messages."
                        ),
                    )
                )

    def _check_langchain_human_message_template(self, node: ast.Call) -> None:
        """Detect HumanMessagePromptTemplate.from_template(dynamic_var)."""
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "from_template"
        ):
            return

        func_value = node.func.value
        obj_name = None
        if isinstance(func_value, ast.Name):
            obj_name = func_value.id
        elif isinstance(func_value, ast.Attribute):
            obj_name = func_value.attr

        if obj_name != "HumanMessagePromptTemplate":
            return

        # The first arg is the template string — flag if it's a bare variable
        # (not a string literal with placeholders)
        if not node.args:
            return

        template_arg = node.args[0]
        if self._is_variable(template_arg) and not isinstance(template_arg, ast.Constant):
            self.findings.append(
                self.rule._make_finding(
                    self.file_path,
                    node.lineno,
                    "Dynamic variable passed to HumanMessagePromptTemplate.from_template — potential prompt injection",
                    self.source_lines,
                    col=node.col_offset,
                    fix_suggestion=(
                        "Pass a static template string with {placeholders} instead of "
                        "a dynamic variable."
                    ),
                )
            )

    # ------------------------------------------------------------------
    # LiteLLM detection helpers
    # ------------------------------------------------------------------

    def _check_litellm_completion(self, node: ast.Call) -> None:
        """Detect litellm.completion/acompletion with dynamic system message content."""
        if not isinstance(node.func, ast.Attribute):
            return

        attr_name = node.func.attr
        if attr_name not in ("completion", "acompletion"):
            return

        # Check that it's called on something that looks like 'litellm'
        func_value = node.func.value
        caller_name = None
        if isinstance(func_value, ast.Name):
            caller_name = func_value.id

        if caller_name != "litellm":
            return

        # Find the messages= keyword arg
        messages_arg = self._get_keyword_arg(node, "messages")
        if messages_arg is None and len(node.args) >= 2:
            messages_arg = node.args[1]

        if messages_arg is None or not isinstance(messages_arg, ast.List):
            return

        for elt in messages_arg.elts:
            if not isinstance(elt, ast.Dict):
                continue
            role_val = None
            content_val = None
            for key, val in zip(elt.keys, elt.values):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                ):
                    if key.value == "role":
                        role_val = val
                    elif key.value == "content":
                        content_val = val

            if (
                role_val is not None
                and isinstance(role_val, ast.Constant)
                and isinstance(role_val.value, str)
                and role_val.value.lower() == "system"
                and content_val is not None
                and self._is_dynamic_string(content_val)
            ):
                self.findings.append(
                    self.rule._make_finding(
                        self.file_path,
                        node.lineno,
                        "Dynamic content in LiteLLM system message — potential prompt injection",
                        self.source_lines,
                        col=node.col_offset,
                        fix_suggestion=(
                            "Use a static system message. Pass user input via "
                            "the user role message instead."
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    # Suffixes that indicate numeric/accounting variables, not strings
    _NUMERIC_SUFFIXES = (
        "_tokens", "_cost", "_count", "_length", "_size",
        "_price", "_usage", "_total",
    )

    @staticmethod
    def _is_numeric_arithmetic(left: ast.expr, right: ast.expr) -> bool:
        """Return True if both operands look like numeric variables.

        Catches patterns like ``prompt_tokens + completion_tokens`` or
        ``prompt_cost + completion_cost`` which are integer/float arithmetic,
        not string concatenation.
        """
        def _is_numeric_name(node: ast.expr) -> bool:
            if isinstance(node, ast.Name):
                name_lower = node.id.lower()
                return any(name_lower.endswith(s) for s in _PromptInjectionVisitor._NUMERIC_SUFFIXES)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return True
            return False

        return _is_numeric_name(left) and _is_numeric_name(right)

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        """Get the simple name of a Call node (e.g. 'PromptTemplate')."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    @staticmethod
    def _get_keyword_arg(node: ast.Call, name: str) -> ast.expr | None:
        """Get the value of a keyword argument by name."""
        for kw in node.keywords:
            if kw.arg == name:
                return kw.value
        return None

    @staticmethod
    def _is_dynamic_string(node: ast.expr) -> bool:
        """Check if a node is a dynamically constructed string.

        Returns True for f-strings (JoinedStr), concatenation (BinOp with Add),
        % formatting (BinOp with Mod), and bare variables.
        Returns False for plain string constants (including those with
        LangChain-style {placeholder} syntax).
        """
        if isinstance(node, ast.JoinedStr):
            # f-string — always dynamic
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call):
            # e.g. "...".format(...)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
            return False
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
            # bare variable reference
            return True
        return False

    @staticmethod
    def _is_prompt_string(node: ast.expr) -> bool:
        """Check if a node is a string constant with prompt-like content."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text_lower = node.value.lower()
            return any(kw in text_lower for kw in _PROMPT_STRING_KEYWORDS)
        if isinstance(node, ast.Name):
            name_lower = node.id.lower()
            return any(kw in name_lower for kw in _PROMPT_KEYWORDS)
        return False

    @staticmethod
    def _is_variable(node: ast.expr) -> bool:
        """Check if a node is a variable reference (not a constant)."""
        return isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))
