"""Intra-procedural taint analysis.

Single-pass, flow-ordered propagation of values derived from an LLM API call
within a function/module scope. Rules use it to confirm that a sink argument
carries LLM output rather than guessing from variable names.

Scope is deliberately small (see docs/superpowers/specs/2026-06-27-llm-taint-
engine-design.md):
  - intra-procedural only (no cross-function tracking)
  - single pass over statements in source order (no control-flow graph), so
    branch/loop precision is approximate
  - LLM source only (user-input source is a later slice)
"""

from __future__ import annotations

import ast
from collections.abc import Iterator

# Taint source labels.
LLM = "llm"
USER = "user"  # reserved for a later slice


def _is_llm_call(node: ast.Call) -> bool:
    """True if the call is a known LLM completion API.

    Recognizes ``*.completions.create``, ``*.messages.create``,
    ``*.ChatCompletion.create`` and ``litellm.completion/acompletion``.
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr == "create":
        parent = func.value
        if isinstance(parent, ast.Attribute) and parent.attr in (
            "messages",
            "completions",
            "ChatCompletion",
        ):
            return True
        return isinstance(parent, ast.Name) and parent.id == "ChatCompletion"
    if func.attr in ("completion", "acompletion"):
        parent = func.value
        return isinstance(parent, ast.Name) and parent.id == "litellm"
    return False


# Flask/Werkzeug/FastAPI request data attributes and inline-read methods.
_REQUEST_DATA = {
    "args", "form", "json", "values", "data", "cookies", "headers",
    "files", "query_params",
}
_REQUEST_METHODS = {"get_json", "get_data"}


def _is_request_root(expr: ast.expr) -> bool:
    """True for the Flask ``request`` object: a bare ``request`` name, or
    ``flask.request`` / ``self.request``.

    The attribute form is restricted to the ``flask``/``self`` receivers on
    purpose: a bare ``.request`` tail on anything else is usually an *outgoing*
    request object (``resp.request.headers`` from the requests/urllib3 client,
    Scrapy ``response.request``, Celery ``self.request`` task context), which is
    not untrusted web input."""
    if isinstance(expr, ast.Name):
        return expr.id == "request"
    return (
        isinstance(expr, ast.Attribute)
        and expr.attr == "request"
        and isinstance(expr.value, ast.Name)
        and expr.value.id in ("flask", "self")
    )


def _is_request_data(expr: ast.expr) -> bool:
    """True for ``request.<data>`` (e.g. ``request.args``, ``request.json``)."""
    return (
        isinstance(expr, ast.Attribute)
        and expr.attr in _REQUEST_DATA
        and _is_request_root(expr.value)
    )


def _is_user_source(expr: ast.expr) -> bool:
    """True if the expression reads untrusted user/CLI/web input.

    Covered: ``input(...)``, ``sys.argv``, ``request.<data>`` and its
    ``.get()``/``.getlist()`` accessors, and ``request.get_json()/get_data()``.
    Matching is structural; a variable literally named ``request`` is assumed to
    be the Flask request (documented limitation — the ``requests`` HTTP client's
    ``.json()`` etc. are deliberately not matched).
    """
    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Name) and func.id == "input":
            return True
        if isinstance(func, ast.Attribute):
            if func.attr in _REQUEST_METHODS and _is_request_root(func.value):
                return True
            if func.attr in ("get", "getlist") and _is_request_data(func.value):
                return True
        return False
    if _is_request_data(expr):
        return True
    return (
        isinstance(expr, ast.Attribute)
        and expr.attr == "argv"
        and isinstance(expr.value, ast.Name)
        and expr.value.id == "sys"
    )


class _ScopeTaint:
    """Taint state for a single scope, built in source order."""

    def __init__(self) -> None:
        self.vars: dict[str, str] = {}  # variable name -> taint source
        self.nodes: dict[int, str] = {}  # id(expr) -> taint source

    def taint_of(self, expr: ast.expr) -> str | None:
        """Return the taint source of an expression and record it on the node."""
        src = self._compute(expr)
        if src:
            self.nodes[id(expr)] = src
        return src

    def _compute(self, expr: ast.expr) -> str | None:
        if _is_user_source(expr):
            return USER
        if isinstance(expr, ast.Call):
            if _is_llm_call(expr):
                return LLM
            return self._compute_call(expr)
        if isinstance(expr, ast.Name):
            return self.vars.get(expr.id)
        if isinstance(expr, (ast.Attribute, ast.Subscript)):
            return self._compute(expr.value)
        if isinstance(expr, ast.JoinedStr):
            return self._compute_joined(expr)
        if isinstance(expr, ast.BinOp):
            return self._compute_binop(expr)
        return None

    def _compute_call(self, expr: ast.Call) -> str | None:
        # "...".format(tainted) or tainted_str.format(...)
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            recv = self._compute(expr.func.value)
            if recv:
                return recv
            for arg in expr.args:
                src = self._compute(arg)
                if src:
                    return src
        return None

    def _compute_joined(self, expr: ast.JoinedStr) -> str | None:
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                src = self._compute(value.value)
                if src:
                    return src
        return None

    def _compute_binop(self, expr: ast.BinOp) -> str | None:
        if isinstance(expr.op, (ast.Add, ast.Mod)):
            return self._compute(expr.left) or self._compute(expr.right)
        return None


def _iter_scopes(tree: ast.Module) -> list[list[ast.stmt]]:
    """Return each scope's statement body: the module top level plus every
    function body. Each is analyzed independently (no cross-scope taint)."""
    scopes: list[list[ast.stmt]] = [tree.body]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append(node.body)
    return scopes


def _iter_stmts(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Yield statements in source order within a scope, descending into
    compound-statement bodies but not crossing nested function/class boundaries
    (those are separate scopes)."""
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield stmt
        for fld in ("body", "orelse", "finalbody"):
            inner = getattr(stmt, fld, None)
            if isinstance(inner, list):
                yield from _iter_stmts(inner)


def _used_exprs(stmt: ast.stmt) -> Iterator[ast.expr]:
    """Yield expression nodes belonging to this statement's own header/value,
    NOT its nested statement bodies.

    Nested bodies (``if``/``for``/``while``/``with``/``try`` bodies and except
    handlers) are visited separately, in source order, by ``_iter_stmts``. If we
    descended into them here we would taint their expressions using the variable
    state from *before* the body runs — e.g. flagging the ``x`` in
    ``if c: x = 'safe'; eval(x)`` as still LLM-tainted. Assignment targets are
    excluded so the LHS of ``x = ...`` is not treated as a use.
    """
    excluded: set[int] = set()
    for tgt in getattr(stmt, "targets", []) or []:
        for node in ast.walk(tgt):
            excluded.add(id(node))

    def _walk(node: ast.AST) -> Iterator[ast.expr]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.stmt, ast.ExceptHandler)):
                continue  # nested body — visited separately in source order
            if isinstance(child, ast.expr):
                if id(child) not in excluded:
                    yield child
                yield from _walk(child)
            else:
                # wrapper nodes (withitem, comprehension, arguments, ...)
                yield from _walk(child)

    yield from _walk(stmt)


def _bind_target(state: _ScopeTaint, target: ast.expr, src: str | None) -> None:
    """Bind a name target to a taint source, or clear it when ``src`` is falsy.

    Tuple/list unpacking targets are conservatively cleared (element-wise taint
    is not tracked). Attribute/subscript targets are ignored (not simple vars)."""
    if isinstance(target, ast.Name):
        if src:
            state.vars[target.id] = src
        else:
            state.vars.pop(target.id, None)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _bind_target(state, elt, None)


def _apply_bindings(state: _ScopeTaint, stmt: ast.stmt) -> None:
    """Update variable taint for any name(s) this statement rebinds.

    Every rebinding form must clear stale taint (so a later clean reassignment
    does not leave a confirmed flow), re-adding taint only when the bound value
    is itself tainted."""
    if isinstance(stmt, ast.Assign):
        src = state.taint_of(stmt.value)
        for tgt in stmt.targets:
            _bind_target(state, tgt, src)
    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        _bind_target(state, stmt.target, state.taint_of(stmt.value))
    elif isinstance(stmt, ast.AugAssign):
        # x op= y : stays tainted if x already was or the rhs is tainted.
        cur = (
            state.vars.get(stmt.target.id)
            if isinstance(stmt.target, ast.Name)
            else None
        )
        _bind_target(state, stmt.target, cur or state.taint_of(stmt.value))
    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
        # Loop variable is rebound each iteration; conservatively clear it.
        _bind_target(state, stmt.target, None)
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            if item.optional_vars is not None:
                _bind_target(state, item.optional_vars, None)


def _run_scope(state: _ScopeTaint, body: list[ast.stmt]) -> None:
    for stmt in _iter_stmts(body):
        # Mark phase: taint this statement's own used expressions (not nested
        # bodies), so sink arguments like the ``x`` in ``eval(x)`` get recorded.
        used = list(_used_exprs(stmt))
        for expr in used:
            state.taint_of(expr)
        # Walrus assignments bind within an expression.
        for expr in used:
            if isinstance(expr, ast.NamedExpr):
                _bind_target(state, expr.target, state.taint_of(expr.value))
        # Update phase: statement-level rebindings mutate variable taint.
        _apply_bindings(state, stmt)


class TaintContext:
    """Per-file taint query object handed to rules."""

    def __init__(self, nodes: dict[int, str]) -> None:
        self._nodes = nodes

    def is_tainted(self, node: ast.expr) -> str | None:
        """Return the taint source of an expression node, or None."""
        return self._nodes.get(id(node))

    @classmethod
    def from_module(cls, tree: ast.Module) -> TaintContext:
        """Build a taint context for every scope in a parsed module."""
        nodes: dict[int, str] = {}
        for body in _iter_scopes(tree):
            state = _ScopeTaint()
            _run_scope(state, body)
            nodes.update(state.nodes)
        return cls(nodes)
