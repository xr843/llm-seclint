# LLM Taint Engine MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an intra-procedural taint engine that flags when an LLM-API-derived value flows into a dangerous sink (LS006), marking such findings as confirmed dataflow — without weakening existing coverage.

**Architecture:** New `analyzers/taint.py` does a single-pass, flow-ordered propagation of LLM-sourced taint within each function/module scope, exposing `TaintContext.is_tainted(node)`. `PythonAnalyzer` builds one context per file and passes it to `rule.check(..., taint=ctx)` (additive optional arg; existing rules ignore it). LS006 consumes it to set `Finding.taint_source` and add a confirmed note.

**Tech Stack:** Python 3.10+, `ast`, pytest, click, rich.

---

### Task 1: `Finding.taint_source` field

**Files:**
- Modify: `src/llm_seclint/core/finding.py`
- Test: `tests/test_finding.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_finding.py
from pathlib import Path
from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity


def test_finding_taint_source_defaults_empty_and_serializes():
    f = Finding(rule_id="LS006", rule_name="x", severity=Severity.HIGH,
                message="m", file_path=Path("a.py"), line=1)
    assert f.taint_source == ""
    assert f.to_dict()["taint_source"] == ""
    f2 = Finding(rule_id="LS006", rule_name="x", severity=Severity.HIGH,
                 message="m", file_path=Path("a.py"), line=1, taint_source="llm")
    assert f2.to_dict()["taint_source"] == "llm"
```

- [ ] **Step 2: Run test, expect FAIL** — `pytest tests/test_finding.py -q` → fails (unexpected kwarg / missing key).

- [ ] **Step 3: Implement** — in `finding.py`, add field after `owasp_llm` and before `metadata`:

```python
    owasp_llm: str = ""
    taint_source: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
```

And add to `to_dict()` after the `owasp_llm` line:

```python
            "owasp_llm": self.owasp_llm,
            "taint_source": self.taint_source,
        }
```

- [ ] **Step 4: Run test, expect PASS.**
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(finding): add taint_source field"`

---

### Task 2: Taint engine — LLM source identification

**Files:**
- Create: `src/llm_seclint/analyzers/taint.py`
- Test: `tests/test_taint.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_taint.py
import ast
from llm_seclint.analyzers.taint import TaintContext, LLM


def _ctx(code: str) -> TaintContext:
    return TaintContext.from_module(ast.parse(code))


def _sink_arg(code: str) -> ast.expr:
    """Return the first arg of the last top-level call expression (the sink)."""
    tree = ast.parse(code)
    call = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][-1]
    return call.args[0]


def test_direct_llm_call_is_tainted():
    code = "import openai\nx = openai.chat.completions.create(model='m')\nuse(x)\n"
    ctx = _ctx(code)
    assert ctx.is_tainted(_sink_arg(code)) == LLM  # use(x): x


def test_llm_call_shapes():
    for call in [
        "client.chat.completions.create(model='m')",
        "openai.ChatCompletion.create(model='m')",
        "litellm.completion(model='m')",
        "litellm.acompletion(model='m')",
        "client.messages.create(model='m')",
    ]:
        code = f"x = {call}\nuse(x)\n"
        assert _ctx(code).is_tainted(_sink_arg(code)) == LLM, call


def test_non_llm_call_not_tainted():
    code = "x = requests.get('u')\nuse(x)\n"
    assert _ctx(code).is_tainted(_sink_arg(code)) is None
```

- [ ] **Step 2: Run test, expect FAIL** (module missing).

- [ ] **Step 3: Implement** — create `taint.py`:

```python
"""Intra-procedural taint analysis.

Single-pass, flow-ordered propagation of values derived from an LLM API call
within a function/module scope. Used by rules to confirm that a sink argument
carries LLM output rather than guessing from names.
"""

from __future__ import annotations

import ast

LLM = "llm"
USER = "user"  # reserved for a later slice


def _is_llm_call(node: ast.Call) -> bool:
    """True if the call is a known LLM completion API."""
    f = node.func
    if not isinstance(f, ast.Attribute):
        return False
    if f.attr == "create":
        parent = f.value
        if isinstance(parent, ast.Attribute) and parent.attr in (
            "messages", "completions", "ChatCompletion",
        ):
            return True
        return isinstance(parent, ast.Name) and parent.id == "ChatCompletion"
    if f.attr in ("completion", "acompletion"):
        parent = f.value
        return isinstance(parent, ast.Name) and parent.id == "litellm"
    return False
```

(The `TaintContext` class is added in Task 5; Tasks 2–4 build the scope analyzer it wraps.)

For Task 2, add a minimal `_ScopeTaint` and `TaintContext.from_module` good enough to pass these tests — recognizing direct LLM calls and simple `x = <llm call>` aliasing. Full propagation lands in Tasks 3–4. Concretely add:

```python
class _ScopeTaint:
    """Taint state for one scope, built in source order."""

    def __init__(self) -> None:
        self.vars: dict[str, str] = {}        # var name -> source
        self.nodes: dict[int, str] = {}       # id(expr) -> source

    def taint_of(self, expr: ast.expr) -> str | None:
        src = self._compute(expr)
        if src:
            self.nodes[id(expr)] = src
        return src

    def _compute(self, expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Call):
            return LLM if _is_llm_call(expr) else None
        if isinstance(expr, ast.Name):
            return self.vars.get(expr.id)
        return None


class TaintContext:
    """Per-file taint query object."""

    def __init__(self, nodes: dict[int, str]) -> None:
        self._nodes = nodes

    def is_tainted(self, node: ast.expr) -> str | None:
        return self._nodes.get(id(node))

    @classmethod
    def from_module(cls, tree: ast.Module) -> "TaintContext":
        nodes: dict[int, str] = {}
        for scope_body in _iter_scopes(tree):
            st = _ScopeTaint()
            _run_scope(st, scope_body)
            nodes.update(st.nodes)
        return cls(nodes)
```

Add the scope helpers `_iter_scopes` (yields the module body and each FunctionDef/AsyncFunctionDef body, not descending across nested defs) and `_run_scope` (Task 3 fills propagation; Task 2 minimal version below):

```python
def _iter_scopes(tree: ast.Module) -> list[list[ast.stmt]]:
    scopes: list[list[ast.stmt]] = [tree.body]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append(node.body)
    return scopes


def _iter_stmts(body: list[ast.stmt]):
    """Yield statements in source order within a scope, not crossing nested
    function/class boundaries; descends into compound-statement bodies."""
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield stmt
        for fld in ("body", "orelse", "finalbody"):
            inner = getattr(stmt, fld, None)
            if isinstance(inner, list):
                yield from _iter_stmts(inner)


def _run_scope(st: "_ScopeTaint", body: list[ast.stmt]) -> None:
    for stmt in _iter_stmts(body):
        # Mark phase: taint every expression used (assignment targets excluded).
        for expr in _used_exprs(stmt):
            st.taint_of(expr)
        # Update phase: assignments mutate var taint.
        if isinstance(stmt, ast.Assign):
            src = st.taint_of(stmt.value)
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    if src:
                        st.vars[tgt.id] = src
                    else:
                        st.vars.pop(tgt.id, None)


def _used_exprs(stmt: ast.stmt):
    """Yield expression nodes referenced by a statement, excluding the names
    being assigned to."""
    targets = set()
    if isinstance(stmt, ast.Assign):
        for tgt in stmt.targets:
            targets.add(id(tgt))
    for node in ast.walk(stmt):
        if isinstance(node, ast.expr) and id(node) not in targets:
            yield node
```

Note: `_used_exprs` walks all sub-expressions so a sink arg like the `x` in `eval(x)` is marked when the engine reaches that statement. Re-marking on each call to `taint_of` is idempotent.

- [ ] **Step 4: Run test, expect PASS.**
- [ ] **Step 5: Commit** — `git commit -am "feat(taint): LLM source identification + scope skeleton"`

---

### Task 3: Propagation — alias, attribute, subscript (extraction chains)

**Files:** Modify `src/llm_seclint/analyzers/taint.py`; Test `tests/test_taint.py`.

- [ ] **Step 1: Write the failing test**

```python
def test_extraction_chain_and_alias():
    code = ("r = openai.chat.completions.create(model='m')\n"
            "x = r.choices[0].message.content\n"
            "y = x\n"
            "use(y)\n")
    assert _ctx(code).is_tainted(_sink_arg(code)) == LLM


def test_attribute_on_clean_is_none():
    code = "r = get_config()\nuse(r.value)\n"
    assert _ctx(code).is_tainted(_sink_arg(code)) is None
```

- [ ] **Step 2: Run, expect FAIL** (extraction chain returns None).

- [ ] **Step 3: Implement** — extend `_ScopeTaint._compute`:

```python
    def _compute(self, expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Call):
            if _is_llm_call(expr):
                return LLM
            # .format() on a tainted string / with tainted args (Task 4)
            return self._compute_call(expr)
        if isinstance(expr, ast.Name):
            return self.vars.get(expr.id)
        if isinstance(expr, (ast.Attribute, ast.Subscript)):
            return self._compute(expr.value)
        if isinstance(expr, ast.JoinedStr):           # Task 4
            return self._compute_joined(expr)
        if isinstance(expr, ast.BinOp):               # Task 4
            return self._compute_binop(expr)
        return None

    def _compute_call(self, expr: ast.Call) -> str | None:
        return None  # filled in Task 4
```

(`_compute_joined`/`_compute_binop` are stubbed `return None` now, implemented in Task 4.)

- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** — `git commit -am "feat(taint): alias/attribute/subscript propagation"`

---

### Task 4: Propagation — string build (f-string / + / % / .format), kill, negatives

**Files:** Modify `taint.py`; Test `tests/test_taint.py`.

- [ ] **Step 1: Write the failing tests**

```python
def test_fstring_and_concat_propagate():
    base = "r = litellm.completion(model='m')\nc = r.content\n"
    for build in ['q = f"x {c} y"', 'q = "x" + c', 'q = "x %s" % c', 'q = "x{}".format(c)']:
        code = base + build + "\nuse(q)\n"
        assert _ctx(code).is_tainted(_sink_arg(code)) == LLM, build


def test_reassignment_kills_taint():
    code = ("r = litellm.completion(model='m')\nx = r.content\n"
            "x = 'safe'\nuse(x)\n")
    assert _ctx(code).is_tainted(_sink_arg(code)) is None


def test_local_and_unrelated_dynamic_not_tainted():
    for code in [
        "x = json.loads(cfg)\nuse(x)\n",
        "x = 1 + 2\nuse(x)\n",
        "use(some_other_var)\n",
    ]:
        assert _ctx(code).is_tainted(_sink_arg(code)) is None
```

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement** — replace the Task-3 stubs:

```python
    def _compute_joined(self, expr: ast.JoinedStr) -> str | None:
        for v in expr.values:
            if isinstance(v, ast.FormattedValue):
                src = self._compute(v.value)
                if src:
                    return src
        return None

    def _compute_binop(self, expr: ast.BinOp) -> str | None:
        if isinstance(expr.op, (ast.Add, ast.Mod)):
            return self._compute(expr.left) or self._compute(expr.right)
        return None

    def _compute_call(self, expr: ast.Call) -> str | None:
        # "...".format(tainted) or tainted_str.format(...)
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            if self._compute(expr.func.value):
                return self._compute(expr.func.value)
            for arg in expr.args:
                src = self._compute(arg)
                if src:
                    return src
        return None
```

- [ ] **Step 4: Run, expect PASS** (also re-run full `tests/test_taint.py`).
- [ ] **Step 5: Commit** — `git commit -am "feat(taint): string-build propagation, kill, negatives"`

---

### Task 5: `check()` seam + `_make_finding` taint_source

**Files:** Modify `src/llm_seclint/rules/base.py`; Test `tests/test_taint.py` (signature) — covered indirectly; add explicit test in Task 7.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_taint.py
def test_rule_check_accepts_taint_kwarg():
    from llm_seclint.rules.python.hardcoded_keys import HardcodedApiKeyRule
    import ast
    from pathlib import Path
    rule = HardcodedApiKeyRule()
    tree = ast.parse("x = 1\n")
    # Must accept taint kwarg without error and behave normally.
    rule.check(tree, Path("a.py"), ["x = 1"], taint=None)
```

- [ ] **Step 2: Run, expect FAIL** (unexpected kwarg).

- [ ] **Step 3: Implement** — in `base.py`:
  - Add import: `from llm_seclint.analyzers.taint import TaintContext` is **not** added (avoid import cycle: analyzer imports rules). Instead type the param loosely.
  - Change the abstract `check` signature in `Rule` to:

```python
    @abc.abstractmethod
    def check(
        self,
        tree: ast.Module,
        file_path: Path,
        source_lines: list[str],
        taint: "object | None" = None,
    ) -> list[Finding]:
        ...
```

  - Update **every** rule's `check` signature to accept `taint: object | None = None` (9 rules in `rules/python/`). Rules that don't use it keep their body unchanged.
  - Extend `_make_finding` with `taint_source: str = ""` param, passed to `Finding(..., taint_source=taint_source)`.

- [ ] **Step 4: Run, expect PASS**; run full suite to confirm no rule broke (`pytest -q`).
- [ ] **Step 5: Commit** — `git commit -am "feat(rules): optional taint arg on check() + _make_finding taint_source"`

---

### Task 6: `PythonAnalyzer` builds and passes the taint context

**Files:** Modify `src/llm_seclint/analyzers/python_analyzer.py`; Test `tests/test_taint.py`.

- [ ] **Step 1: Write the failing test**

```python
def test_analyzer_passes_taint_to_rules():
    from pathlib import Path
    from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
    from llm_seclint.rules.python.insecure_deserialization import InsecureDeserializationRule
    code = ("r = litellm.completion(model='m')\nx = r.content\neval(x)\n")
    findings, err = PythonAnalyzer([InsecureDeserializationRule()]).analyze(code, Path("a.py"))
    assert err is None
    ls006 = [f for f in findings if f.rule_id == "LS006"]
    assert ls006 and ls006[0].taint_source == "llm"
```

- [ ] **Step 2: Run, expect FAIL** (taint_source empty until Task 7 wires LS006; this test passes only after Task 7 — order: write it here, leave failing, satisfied at Task 7 Step 4). Mark with a note; OR move this test to Task 7. **Decision: move this assertion to Task 7.** In Task 6, assert only that analyze runs with taint wired:

```python
def test_analyzer_builds_taint_context_without_error():
    from pathlib import Path
    from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
    from llm_seclint.rules.python.hardcoded_keys import HardcodedApiKeyRule
    code = "r = litellm.completion(model='m')\nx = r.content\n"
    findings, err = PythonAnalyzer([HardcodedApiKeyRule()]).analyze(code, Path("a.py"))
    assert err is None
```

- [ ] **Step 3: Implement** — in `python_analyzer.py`:
  - Import: `from llm_seclint.analyzers.taint import TaintContext`
  - In `analyze`, after `tree = ast.parse(...)` and before the rule loop, build the context with safe degradation:

```python
        try:
            taint = TaintContext.from_module(tree)
        except Exception:  # noqa: BLE001 - taint must never break a scan
            taint = TaintContext({})

        source_lines = source.splitlines()
        findings: list[Finding] = []

        for rule in self.rules:
            rule_findings = rule.check(tree, file_path, source_lines, taint=taint)
            findings.extend(rule_findings)
```

- [ ] **Step 4: Run, expect PASS**; full suite green.
- [ ] **Step 5: Commit** — `git commit -am "feat(analyzer): build taint context and pass to rules"`

---

### Task 7: LS006 consumes taint (enhancement-only)

**Files:** Modify `src/llm_seclint/rules/python/insecure_deserialization.py`; Test `tests/rules/test_insecure_deserialization.py`.

- [ ] **Step 1: Write the failing tests**

```python
def test_ls006_confirmed_llm_dataflow(_make_analyzer=None):
    from pathlib import Path
    from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
    from llm_seclint.rules.python.insecure_deserialization import InsecureDeserializationRule
    code = "r = litellm.completion(model='m')\nx = r.content\neval(x)\n"
    findings, _ = PythonAnalyzer([InsecureDeserializationRule()]).analyze(code, Path("a.py"))
    f = [f for f in findings if f.rule_id == "LS006"][0]
    assert f.taint_source == "llm"
    assert "confirmed" in f.message.lower()


def test_ls006_plain_dynamic_unchanged():
    from pathlib import Path
    from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
    from llm_seclint.rules.python.insecure_deserialization import InsecureDeserializationRule
    code = "x = get_local()\neval(x)\n"
    findings, _ = PythonAnalyzer([InsecureDeserializationRule()]).analyze(code, Path("a.py"))
    f = [f for f in findings if f.rule_id == "LS006"][0]
    assert f.taint_source == ""
    assert "confirmed" not in f.message.lower()
```

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement** — update LS006 `check` to accept and use taint:
  - Signature: `def check(self, tree, file_path, source_lines, taint=None):`
  - When building the finding (the `has_dynamic` branch), compute the confirmed source from the dynamic arg(s):

```python
            has_dynamic = any(self._is_dynamic(arg) for arg in node.args)
            if not has_dynamic:
                continue

            src = ""
            if taint is not None:
                for arg in node.args:
                    s = taint.is_tainted(arg)
                    if s:
                        src = s
                        break

            message = f"Dynamic input passed to {func_display}"
            if src:
                message += f" — confirmed {src.upper()}→sink dataflow"

            findings.append(
                self._make_finding(
                    file_path, node.lineno, message, source_lines,
                    col=node.col_offset, fix_suggestion=suggestion,
                    taint_source=src,
                )
            )
```

- [ ] **Step 4: Run, expect PASS** (`pytest tests/rules/test_insecure_deserialization.py tests/test_taint.py -q`).
- [ ] **Step 5: Commit** — `git commit -am "feat(LS006): mark confirmed LLM->sink dataflow via taint"`

---

### Task 8: Text formatter shows the confirmed marker

**Files:** Modify `src/llm_seclint/formatters/text.py`; Test `tests/test_formatters.py`.

- [ ] **Step 1: Write the failing test** — add to `tests/test_formatters.py`:

```python
def test_text_formatter_shows_confirmed_marker():
    from llm_seclint.formatters.text import TextFormatter
    from llm_seclint.core.finding import Finding
    from llm_seclint.core.severity import Severity
    from pathlib import Path
    f = Finding(rule_id="LS006", rule_name="insecure-deserialization",
                severity=Severity.HIGH, message="Dynamic input passed to eval()",
                file_path=Path("a.py"), line=3, taint_source="llm")
    out = TextFormatter(use_color=False).format([f], 0.0, file_count=1)
    assert "confirmed" in out.lower() or "LLM→sink" in out or "llm" in out.lower()
```

- [ ] **Step 2: Run, expect FAIL** (marker not shown). Inspect `text.py` first to find the per-finding render line; the marker is appended there. If the message already carries "confirmed …" (Task 7), this test may already pass — in that case the formatter change is to add a distinct visual tag (e.g. a `[confirmed:llm]` chip) and assert on that instead. Adjust the assertion to the chosen tag.

- [ ] **Step 3: Implement** — in the finding-rendering loop of `text.py`, when `finding.taint_source`, append a tag to the rendered line, e.g. ` [confirmed:{finding.taint_source}]`.

- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** — `git commit -am "feat(text): show confirmed taint marker"`

---

### Task 9: Regression + dogfood + lint

**Files:** none (verification); add a regression example if useful.

- [ ] **Step 1:** Add a confirmed-dataflow case to `examples/vulnerable_app.py` only if it doesn't already exist as a plain dynamic; otherwise skip (YAGNI).
- [ ] **Step 2:** `ruff check src/ tests/` → All checks passed.
- [ ] **Step 3:** `pytest -q` → all green (existing + new).
- [ ] **Step 4:** `llm-seclint scan examples/secure_app.py` → exit 0 (still clean).
- [ ] **Step 5:** `llm-seclint scan examples/vulnerable_app.py` → finding **count unchanged** vs main; the eval/pickle LS006 lines now carry the confirmed marker if their arg is taint-traced.
- [ ] **Step 6:** `llm-seclint scan src/` → exit 0 (self-scan clean).
- [ ] **Step 7: Commit** any example/doc tweaks — `git commit -am "test: taint MVP regression + dogfood"`

---

## Self-Review notes

- **Spec coverage:** source id (T2), propagation incl. chains/string-build/kill/negatives (T3–T4), `TaintContext.is_tainted` (T2/T5), additive `check(...,taint=)` seam (T5), analyzer wiring + safe degradation (T6), LS006 enhancement-only with `taint_source` + note (T7), `Finding.taint_source` + formatter (T1/T8), tests incl. secure_app/vulnerable_app regression (T9). LS003/LS004/user-source explicitly deferred.
- **Import cycle:** `python_analyzer` imports `taint`; `taint` imports only `ast`. `base.py` types the `taint` param as `object | None` to avoid importing `TaintContext` (rules are imported by the analyzer). No cycle.
- **Severity unchanged:** Task 7 only edits the message + sets `taint_source`; it does not touch `self.severity`, matching the spec.
- **Flow approximation:** single-pass over source-ordered statements; branch/loop precision is out of scope (documented).
