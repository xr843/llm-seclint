"""Tests for the intra-procedural taint engine."""

from __future__ import annotations

import ast

from llm_seclint.analyzers.taint import LLM, USER, TaintContext


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


def test_kill_inside_compound_statement() -> None:
    # Reassignment to a clean value inside an if/for/try/with body must clear
    # taint (regression: single-pass must respect in-block kills).
    for header in ["if cond:", "for i in items:", "while cond:", "with ctx():"]:
        code = (
            "r = litellm.completion(model='m')\n"
            "x = r.content\n"
            f"{header}\n"
            "    x = 'safe'\n"
            "    use(x)\n"
        )
        assert _analyze(code) is None, header


def test_sink_inside_compound_still_confirmed() -> None:
    # The kill fix must not silence a genuine flow inside a compound body.
    code = (
        "r = litellm.completion(model='m')\n"
        "x = r.content\n"
        "if cond:\n"
        "    use(x)\n"
    )
    assert _analyze(code) == LLM


def test_non_assign_rebinds_kill_taint() -> None:
    base = "x = litellm.completion(model='m').content\n"
    for rebind in [
        "x: str = 'safe'",          # AnnAssign
        "(x := 'safe')",            # walrus
        "for x in clean_list():\n    pass",  # for-target
    ]:
        code = base + rebind + "\nuse(x)\n"
        assert _analyze(code) is None, rebind


def test_with_as_target_not_tainted() -> None:
    code = (
        "x = litellm.completion(model='m').content\n"
        "with open('f') as x:\n"
        "    use(x)\n"
    )
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


# --- Integration seam (Task 5) ---


def test_rule_check_accepts_taint_kwarg() -> None:
    from pathlib import Path

    from llm_seclint.rules.python.hardcoded_keys import HardcodedApiKeyRule

    rule = HardcodedApiKeyRule()
    tree = ast.parse("x = 1\n")
    # Must accept the taint kwarg without error and behave normally.
    assert rule.check(tree, Path("a.py"), ["x = 1"], taint=None) == []


# --- User-input source (Task: PR #6) ---


def test_user_source_input() -> None:
    assert _analyze("x = input()\nuse(x)\n") == USER
    assert _analyze("x = input('prompt> ')\nuse(x)\n") == USER


def test_user_source_shapes() -> None:
    for src in [
        "sys.argv",
        "sys.argv[1]",
        "request.args.get('q')",
        "request.form['name']",
        "request.json",
        "request.values.get('x')",
        "request.get_json()",
        "request.data",
    ]:
        assert _analyze(f"x = {src}\nuse(x)\n") == USER, src


def test_user_source_propagates_through_build() -> None:
    code = "raw = request.args.get('q')\nq = f'SELECT * FROM t WHERE n={raw}'\nuse(q)\n"
    assert _analyze(code) == USER


def test_requests_library_is_not_user_source() -> None:
    # The `requests` HTTP client and an arbitrary `.json()` are NOT user input.
    for code in [
        "x = requests.get(url)\nuse(x)\n",
        "resp = http.get(url)\nx = resp.json()\nuse(x)\n",
        "x = other.data\nuse(x)\n",
    ]:
        assert _analyze(code) is None, code


def test_outgoing_request_attribute_not_user_source() -> None:
    # `.request` tails on non-flask/self receivers are outgoing-request objects
    # (requests/urllib3/Scrapy), not untrusted input.
    for code in [
        "use(resp.request.headers)\n",
        "use(response.request.cookies)\n",
        "use(client.request.data)\n",
    ]:
        assert _analyze(code) is None, code
    # flask.request / self.request stay recognized.
    assert _analyze("use(flask.request.args)\n") == USER
    assert _analyze("use(self.request.data)\n") == USER


def test_user_to_sink_confirmed_via_rule() -> None:
    # End-to-end: a user-input value reaching a sink is confirmed as USER.
    from pathlib import Path

    from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
    from llm_seclint.rules.python.insecure_deserialization import (
        InsecureDeserializationRule,
    )

    code = "raw = request.args.get('code')\neval(raw)\n"
    findings, _ = PythonAnalyzer([InsecureDeserializationRule()]).analyze(
        code, Path("a.py")
    )
    f = [x for x in findings if x.rule_id == "LS006"][0]
    assert f.taint_source == "user"
    assert "USER→sink" in f.message


def test_percent_tuple_and_format_kwargs_propagate() -> None:
    # Regression (review): printf %-tuple RHS and .format(**kwargs) must propagate.
    base = "u = request.args.get('q')\n"
    for build in [
        'q = "x %s" % (u,)',          # single-element tuple
        'q = "x %s %s" % (a, u)',     # multi-element tuple
        'q = "x {n}".format(n=u)',    # keyword arg
    ]:
        assert _analyze(base + build + "\nuse(q)\n") == USER, build
