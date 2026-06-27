# LLM Taint Engine — MVP Design

**Date:** 2026-06-27
**Status:** Approved (design), pending implementation plan
**Scope:** First vertical slice of intra-procedural taint analysis for llm-seclint

## Problem

llm-seclint's marketing promise is *"find where LLM output flows into a dangerous
sink."* Today the rules do not actually track data flow — they match sink calls
with dynamic arguments and guess the data's origin from string content / variable
names. This makes the LLM-specific claim aspirational and overlaps heavily with
Bandit (B608, B602, B301/B307, etc.). The experimental rules (LS002, LS003) over-
report precisely because they cannot tell whether a value is LLM/user-derived.

A real, if modest, taint engine is the only thing that differentiates this tool
from Bandit/Semgrep. This spec defines the **first vertical slice** that proves
the approach on one sink rule without boiling the ocean.

## Goals (this slice)

1. Build a reusable **intra-procedural** taint engine that identifies values
   originating from an LLM API call and propagates that "taint" within a function
   body.
2. Wire it into **LS006** (`insecure-deserialization`: `eval`/`exec`/`compile`/
   `pickle`/unsafe YAML) so a finding whose sink argument is *confirmed* to carry
   LLM output is marked high-confidence — **without weakening** LS006's existing
   coverage of merely-dynamic arguments.
3. Establish the integration seam (`check(..., taint=ctx)`) and the `Finding`
   field so LS003/LS004 (slice 2) and LS002/user-input sources (slice 3) can be
   added later with no rework.

## Non-goals (explicitly out of this slice)

- **No inter-procedural analysis** (no tracking across function-call boundaries).
- **No control-flow graph / fixed-point iteration** — single-pass approximation
  only (see Approach).
- **No user-input source** yet (that is slice 3, enabling LS002).
- **No new sink types** — sinks come only from existing rules.
- **No rewrite of the `check()` signature** for all rules — additive optional
  parameter only.
- LS003/LS004 wiring is slice 2, not here.

## Approach decisions

### Taint precision: single-pass def-use approximation

Within each function scope, walk statements in source order maintaining a set of
tainted variable names. This covers the dominant real-world shape
(`r = llm(); x = r.content; eval(x)`), is fast and simple, and is good enough to
prove value. It does **not** precisely model `if/else` branches or loop back-edges
(it approximates by source order); the limitation is documented and a CFG-based
upgrade is left as a future option. Chosen over a formal CFG + fixed-point engine,
which is itself multi-week work and disproportionate for an MVP.

### Rule integration: additive optional `taint` parameter

`Rule.check()` gains an optional `taint: TaintContext | None = None` argument.
Existing rules ignore it (zero breakage); wired rules consume it. Chosen over a
`RuleContext` refactor of all nine rules, which is cleaner long-term but a large
breaking change — deferred to a later cleanup, not this slice.

## Architecture

### New module: `src/llm_seclint/analyzers/taint.py`

**`TaintSource`** — enum-like string constants: `"llm"` (this slice), `"user"`
(reserved for slice 3).

**`build_taint(scope_node: ast.AST) -> dict[int, TaintSource]`**
Single-pass builder over one scope (a `FunctionDef`/`AsyncFunctionDef` body, or
module top level). Returns a map from the `id()` of tainted expression nodes to
their source. Internally maintains `tainted_vars: dict[str, TaintSource]` updated
in statement order.

**`TaintContext`** — the query object handed to rules. Built once per file from
all scopes. Public surface:
- `is_tainted(node: ast.expr) -> TaintSource | None` — returns the taint source
  of an expression node, or `None`.

The context is intentionally minimal: rules ask "is this argument tainted?" and
get back a source label or nothing. They cannot see the engine internals.

### Source identification (LLM only, this slice)

A call expression is an LLM source if it matches a known completion API:
- `openai.chat.completions.create(...)`, `client.chat.completions.create(...)`,
  `openai.ChatCompletion.create(...)`
- `litellm.completion(...)`, `litellm.acompletion(...)`
- Anthropic `*.messages.create(...)`

The call's return value is tainted. Common extraction chains keep the taint:
`.choices[0].message.content`, `.content`, `.text`, `.message.content`. Matching
is structural on the attribute/call shape (mirrors the patterns LS002 already
recognizes), not on variable names.

### Propagation rules (single pass, in statement order)

Given the current `tainted_vars`:
- **Assignment** `x = <expr>`: if `<expr>` is tainted, add `x`; otherwise remove
  `x` (kill — reassignment to a clean value clears taint).
- **Alias** `x = y` where `y` is tainted: `x` inherits `y`'s source.
- **String build**: an f-string (`JoinedStr`), `+` concatenation (`BinOp/Add`), or
  `"...".format(tainted)` / `% tainted` is tainted if **any** dynamic part is
  tainted.
- **Attribute / subscript**: `x.attr`, `x[i]` are tainted if `x` is tainted (so
  the extraction chains above propagate).
- **Direct source**: a recognized LLM call expression is tainted wherever it
  appears (including inline, e.g. `eval(llm().content)`).

Tuple/list unpacking and augmented assignment beyond the above are treated
conservatively as **not tainted** (safe default — may under-report, never over-
escalate).

### Data flow / wiring

1. `PythonAnalyzer.analyze()` parses the AST (unchanged), then calls a builder
   that walks every `FunctionDef`/`AsyncFunctionDef` and the module top level,
   constructing a single `TaintContext` covering all scopes.
2. The context is passed to every rule: `rule.check(tree, file_path, source_lines,
   taint=ctx)`.
3. LS006 (`InsecureDeserializationRule`) consumes it. For each dangerous call with
   a dynamic argument:
   - if `taint.is_tainted(arg)` is truthy → emit the finding with
     `taint_source` set (e.g. `"llm"`); the message gains a
     `confirmed LLM→sink dataflow` note. **Severity is unchanged** — the
     enhancement is the note plus the structured `taint_source` field (which
     lets users sort/filter for confirmed flows). Raising severity is left to a
     future slice to avoid perturbing the min-severity filter and its tests.
   - otherwise → **existing behavior unchanged** (still reported as a dynamic-
     input finding, no taint note).

### `Finding` change

Add `taint_source: str = ""` to the `Finding` dataclass. Formatters render a
`confirmed LLM→sink` marker when it is set (text, JSON, SARIF). Empty string =
today's behavior, so all existing output is unaffected when no taint is confirmed.

## Error handling

The taint engine must never make the scan worse:
- Any unsupported node, unexpected structure, or internal exception during taint
  building degrades safely to **"not tainted"** for the affected scope/node.
- A rule that receives `taint=None` (or an empty context) behaves exactly as it
  does today.
- Taint can only **add** confidence/notes to findings or let an experimental rule
  narrow; it can never suppress an existing stable finding or raise a false
  finding on a clean value. (LS006 still reports merely-dynamic args.)

## Testing

**Taint engine unit tests** (`tests/test_taint.py`):
- Source recognition: each supported LLM API shape returns `"llm"`.
- Extraction chains: `.choices[0].message.content`, `.content`, `.text` stay
  tainted.
- Propagation: alias, f-string/`+`/`.format()`/`%`, attribute, subscript.
- Kill: reassignment to a clean value clears taint.
- Negatives: local constants, `json.loads(config)`, unrelated dynamic variables,
  and numeric expressions are **not** tainted (guards against over-tainting).

**LS006 integration tests** (extend `tests/rules/test_insecure_deserialization.py`):
- `eval`/`exec`/`pickle.loads` on a taint-confirmed LLM value → finding with
  `taint_source == "llm"` and the confirmed note.
- `eval` on a merely-dynamic local value → finding still emitted, `taint_source`
  empty (coverage preserved).

**Regression**: `examples/secure_app.py` stays clean (exit 0);
`examples/vulnerable_app.py` default scan unchanged in finding count; full suite
green; ruff clean; self-scan clean.

## Future slices (not this work)

- **Slice 2**: wire LS003 (SQL) and LS004 (shell) to taint; LS003 narrows to
  taint-only and graduates from experimental to stable.
- **Slice 3**: add `"user"` source (`input()`, Flask/FastAPI `request.*`); wire
  LS002 (prompt injection) to taint and graduate it.
- **Later**: CFG + fixed-point precision (axis 1 upgrade); `RuleContext` refactor
  (axis 2 cleanup); README "How It Works" update to describe real data-flow.
