"""Tests for LS002: Prompt concatenation injection detection."""

from __future__ import annotations

from llm_seclint.rules.python.prompt_injection import PromptConcatInjectionRule
from tests.conftest import run_rule_on_code


def _rule() -> PromptConcatInjectionRule:
    return PromptConcatInjectionRule()


class TestPromptConcatInjection:
    def test_fstring_prompt(self) -> None:
        code = 'prompt = f"You are a helpful bot. User says: {user_input}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "LS002"

    def test_concat_prompt(self) -> None:
        code = 'prompt = "You are a helpful assistant. User input: " + user_input'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_format_prompt(self) -> None:
        code = 'prompt = "You are a bot. The user says: {msg}".format(msg=user_input)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_system_fstring(self) -> None:
        code = 'msg = f"Your task is to respond to {query}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_safe_separate_messages(self) -> None:
        code = '''
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": user_input},
]
'''
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_static_string(self) -> None:
        code = 'prompt = "You are a helpful assistant."'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_non_prompt_fstring(self) -> None:
        code = 'msg = f"Hello {name}, welcome!"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0


class TestPercentFormatting:
    def test_percent_formatting_prompt(self) -> None:
        code = 'prompt = "You are a bot. User says: %s" % user_input'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "LS002"
        assert "% formatting" in findings[0].message

    def test_percent_formatting_safe(self) -> None:
        code = 'msg = "Hello %s" % name'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0


class TestLangChainPromptTemplate:
    def test_prompt_template_fstring(self) -> None:
        """PromptTemplate with f-string template should trigger."""
        code = 'pt = PromptTemplate(template=f"You are a bot. Answer: {user_input}")'
        findings = run_rule_on_code(_rule(), code)
        # Should trigger both the f-string detection AND the LangChain detection
        assert len(findings) >= 1
        assert any("LS002" == f.rule_id for f in findings)

    def test_prompt_template_concat(self) -> None:
        """PromptTemplate with concatenated template should trigger."""
        code = 'pt = PromptTemplate(template="You are a system bot. " + user_input)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_prompt_template_static_placeholders(self) -> None:
        """PromptTemplate with static template string and {placeholders} should NOT trigger."""
        code = 'pt = PromptTemplate(template="Tell me about {topic}")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0


class TestLangChainChatPromptTemplate:
    def test_chat_prompt_template_dynamic_system(self) -> None:
        """ChatPromptTemplate.from_messages with dynamic system message should trigger."""
        code = '''
prompt = ChatPromptTemplate.from_messages([
    ("system", f"You are a {persona} assistant"),
    ("user", "{input}"),
])
'''
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1
        assert any("ChatPromptTemplate" in f.message for f in findings)

    def test_chat_prompt_template_static_system(self) -> None:
        """ChatPromptTemplate.from_messages with static system message should NOT trigger."""
        code = '''
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant"),
    ("user", "{input}"),
])
'''
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_chat_prompt_template_dynamic_user_only(self) -> None:
        """Dynamic content in user role only should NOT trigger the ChatPromptTemplate check."""
        code = '''
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant"),
    ("user", f"Tell me about {topic}"),
])
'''
        findings = run_rule_on_code(_rule(), code)
        # The f-string in user role may or may not trigger the generic f-string check,
        # but it should NOT trigger the ChatPromptTemplate system-message check
        assert not any("ChatPromptTemplate" in f.message for f in findings)


class TestLangChainHumanMessagePromptTemplate:
    def test_human_message_template_dynamic_var(self) -> None:
        """HumanMessagePromptTemplate.from_template(var) should trigger."""
        code = 'msg = HumanMessagePromptTemplate.from_template(user_input)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1
        assert any("HumanMessagePromptTemplate" in f.message for f in findings)

    def test_human_message_template_static_string(self) -> None:
        """HumanMessagePromptTemplate.from_template("static {placeholder}") should NOT trigger."""
        code = 'msg = HumanMessagePromptTemplate.from_template("Tell me about {topic}")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0


class TestLiteLLMCompletion:
    def test_litellm_completion_dynamic_system(self) -> None:
        """litellm.completion with dynamic system message should trigger."""
        code = '''
response = litellm.completion(
    model="gpt-4",
    messages=[
        {"role": "system", "content": f"You are a {persona} assistant"},
        {"role": "user", "content": user_query},
    ],
)
'''
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1
        assert any("LiteLLM" in f.message for f in findings)

    def test_litellm_acompletion_dynamic_system(self) -> None:
        """litellm.acompletion with dynamic system message should trigger."""
        code = '''
response = litellm.acompletion(
    model="gpt-4",
    messages=[
        {"role": "system", "content": f"You are a {persona} assistant"},
        {"role": "user", "content": user_query},
    ],
)
'''
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1
        assert any("LiteLLM" in f.message for f in findings)

    def test_litellm_completion_static_system(self) -> None:
        """litellm.completion with static system message should NOT trigger."""
        code = '''
response = litellm.completion(
    model="gpt-4",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": user_query},
    ],
)
'''
        findings = run_rule_on_code(_rule(), code)
        # Should NOT trigger the LiteLLM-specific check
        assert not any("LiteLLM" in f.message for f in findings)

    def test_litellm_completion_dynamic_user_only(self) -> None:
        """litellm.completion with dynamic user message only should NOT trigger LiteLLM check."""
        code = '''
response = litellm.completion(
    model="gpt-4",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": f"Tell me about {topic}"},
    ],
)
'''
        findings = run_rule_on_code(_rule(), code)
        assert not any("LiteLLM" in f.message for f in findings)


class TestFalsePositiveReduction:
    """Ensure generic non-LLM code does NOT trigger LS002."""

    def test_logging_query(self) -> None:
        code = 'msg = f"Processing query {q}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_system_status(self) -> None:
        code = 'msg = f"The system {name} is running"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_statistics(self) -> None:
        code = 'msg = f"statistic for {account_id}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_oauth_redirect(self) -> None:
        code = 'msg = f"redirect to {oauth_url}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_answer_generic(self) -> None:
        code = 'msg = f"The answer is {result}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_question_generic(self) -> None:
        code = 'msg = f"Question {num}: {text}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_concat_system_generic(self) -> None:
        code = 'msg = "The system " + name + " is ready"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_respond_generic(self) -> None:
        code = 'msg = f"Failed to respond to {request_id}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0


class TestNumericArithmeticFalsePositives:
    """Ensure token/cost arithmetic does NOT trigger LS002."""

    def test_safe_token_arithmetic(self) -> None:
        code = 'total = prompt_tokens + completion_tokens'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_cost_arithmetic(self) -> None:
        code = 'total_cost = prompt_cost + completion_cost'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_count_arithmetic(self) -> None:
        code = 'total_count = prompt_count + completion_count'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_usage_arithmetic(self) -> None:
        code = 'total_usage = prompt_usage + completion_usage'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_length_arithmetic(self) -> None:
        code = 'total_length = prompt_length + completion_length'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0


class TestTruePositiveRetention:
    """Ensure actual prompt injection patterns STILL trigger LS002."""

    def test_fstring_you_are_user_says(self) -> None:
        code = 'prompt = f"You are a helpful assistant. User says: {user_input}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_fstring_as_a_role(self) -> None:
        code = 'prompt = f"As a {role}, respond to: {input}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_concat_your_task(self) -> None:
        code = 'prompt = "Your task is to " + user_input'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_fstring_system_prompt(self) -> None:
        code = 'msg = f"system prompt: {instructions}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_fstring_user_query(self) -> None:
        code = 'prompt = f"Answer the user query: {q}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_format_your_role(self) -> None:
        code = 'prompt = "Your role is {role}. Context: {ctx}".format(role=r, ctx=c)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1


class TestLs002TaintEnhancement:
    """LS002 stays experimental + broad, but annotates the taint-confirmed subset."""

    def test_confirmed_user_to_prompt(self) -> None:
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        code = (
            "name = request.args.get('n')\n"
            'prompt = f"You are a bot. User says: {name}"\n'
        )
        findings, _ = PythonAnalyzer([_rule()]).analyze(code, Path("app.py"))
        f = [x for x in findings if x.rule_id == "LS002"][0]
        assert f.taint_source == "user"
        assert "confirmed" in f.message.lower()

    def test_broad_heuristic_still_fires_unconfirmed(self) -> None:
        # A prompt built from an unconfirmable param is still reported (no note),
        # so the heuristic's coverage is unchanged by taint.
        from pathlib import Path

        from llm_seclint.analyzers.python_analyzer import PythonAnalyzer

        code = 'prompt = f"You are a bot. User says: {user_msg}"\n'
        findings, _ = PythonAnalyzer([_rule()]).analyze(code, Path("app.py"))
        f = [x for x in findings if x.rule_id == "LS002"][0]
        assert f.taint_source == ""
        assert "confirmed" not in f.message.lower()
