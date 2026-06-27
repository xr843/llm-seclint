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
    """Yield expression nodes referenced by a statement, excluding the names
    being assigned to (so the LHS of ``x = ...`` is not treated as a use)."""
    targets: set[int] = set()
    if isinstance(stmt, ast.Assign):
        for tgt in stmt.targets:
            targets.add(id(tgt))
    for node in ast.walk(stmt):
        if isinstance(node, ast.expr) and id(node) not in targets:
            yield node


def _run_scope(state: _ScopeTaint, body: list[ast.stmt]) -> None:
    for stmt in _iter_stmts(body):
        # Mark phase: taint every used expression (assignment targets excluded),
        # so sink arguments like the ``x`` in ``eval(x)`` get recorded.
        for expr in _used_exprs(stmt):
            state.taint_of(expr)
        # Update phase: a plain assignment mutates variable taint.
        if isinstance(stmt, ast.Assign):
            src = state.taint_of(stmt.value)
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    if src:
                        state.vars[tgt.id] = src
                    else:
                        state.vars.pop(tgt.id, None)


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
