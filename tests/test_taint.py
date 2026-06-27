"""Tests for the intra-procedural taint engine."""

from __future__ import annotations

import ast

from llm_seclint.analyzers.taint import LLM, TaintContext


def _analyze(code: str) -> str | None:
    """Build a TaintContext from code and return the taint of the argument
    wrapped in the marker call ``use(<expr>)``.

    The context and the queried node come from the SAME parse tree because the
    engine keys results on ``id(node)``.
    """
    tree = ast.parse(code)
    ctx = TaintContext.from_module(tree)
    use_call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "use"
    )
    return ctx.is_tainted(use_call.args[0])


# --- Source identification (Task 2) ---


def test_direct_llm_call_is_tainted() -> None:
    assert _analyze("x = openai.chat.completions.create(model='m')\nuse(x)\n") == LLM


def test_llm_call_shapes() -> None:
    for call in [
        "client.chat.completions.create(model='m')",
        "openai.ChatCompletion.create(model='m')",
        "litellm.completion(model='m')",
        "litellm.acompletion(model='m')",
        "client.messages.create(model='m')",
    ]:
        assert _analyze(f"x = {call}\nuse(x)\n") == LLM, call


def test_inline_llm_call_is_tainted() -> None:
    assert _analyze("use(litellm.completion(model='m').content)\n") == LLM


def test_non_llm_call_not_tainted() -> None:
    assert _analyze("x = requests.get('u')\nuse(x)\n") is None


# --- Propagation: alias / attribute / subscript (Task 3) ---


def test_extraction_chain_and_alias() -> None:
    code = (
        "r = openai.chat.completions.create(model='m')\n"
        "x = r.choices[0].message.content\n"
        "y = x\n"
        "use(y)\n"
    )
    assert _analyze(code) == LLM


def test_attribute_on_clean_is_none() -> None:
    assert _analyze("r = get_config()\nuse(r.value)\n") is None


# --- Propagation: string build / kill / negatives (Task 4) ---


def test_fstring_and_concat_propagate() -> None:
    base = "r = litellm.completion(model='m')\nc = r.content\n"
    for build in [
        'q = f"x {c} y"',
        'q = "x" + c',
        'q = "x %s" % c',
        'q = "x{}".format(c)',
    ]:
        assert _analyze(base + build + "\nuse(q)\n") == LLM, build


def test_reassignment_kills_taint() -> None:
    code = (
        "r = litellm.completion(model='m')\n"
        "x = r.content\n"
        "x = 'safe'\n"
        "use(x)\n"
    )
    assert _analyze(code) is None


def test_local_and_unrelated_dynamic_not_tainted() -> None:
    for code in [
        "x = json.loads(cfg)\nuse(x)\n",
        "x = 1 + 2\nuse(x)\n",
        "use(some_other_var)\n",
    ]:
        assert _analyze(code) is None


def test_taint_is_scoped_per_function() -> None:
    # taint in one function must not leak into another.
    code = (
        "def a():\n"
        "    r = litellm.completion(model='m')\n"
        "    x = r.content\n"
        "    use(x)\n"
        "def b(x):\n"
        "    use(x)\n"
    )
    tree = ast.parse(code)
    ctx = TaintContext.from_module(tree)
    uses = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "use"
    ]
    assert ctx.is_tainted(uses[0].args[0]) == LLM  # inside a()
    assert ctx.is_tainted(uses[1].args[0]) is None  # inside b(), param x
