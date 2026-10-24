"""Semantics-preserving simplification of expression trees.

Rules applied bottom-up until nothing changes:

* flatten nested ``And``/``Or`` of the same kind (associativity);
* drop duplicate children (idempotence), keeping first-seen order;
* constant folding: ``And`` with ``false`` is ``false``, ``true`` children vanish, and dually
  for ``Or``; ``Not(Const)`` folds;
* a single child replaces its parent; ``Not(Not(x))`` is ``x``.

Every rule is a Boolean-algebra identity, so the result matches exactly the same events. The
property tests check this against the reference evaluator on random trees.
"""

from __future__ import annotations

from sigmaforge.ast import And, Const, Node, Not, Or


def simplify(node: Node) -> Node:
    if isinstance(node, Not):
        child = simplify(node.child)
        if isinstance(child, Not):
            return child.child
        if isinstance(child, Const):
            return Const(not child.value)
        return Not(child)
    if isinstance(node, And | Or):
        is_and = isinstance(node, And)
        neutral, absorbing = (True, False) if is_and else (False, True)
        out: list[Node] = []
        seen: set[Node] = set()
        for child in node.children:
            child = simplify(child)
            same_kind = isinstance(child, And | Or) and isinstance(child, And) == is_and
            nested = child.children if isinstance(child, And | Or) and same_kind else (child,)
            for item in nested:
                if isinstance(item, Const):
                    if item.value == absorbing:
                        return Const(absorbing)
                    continue
                if item not in seen:
                    seen.add(item)
                    out.append(item)
        if not out:
            return Const(neutral)
        if len(out) == 1:
            return out[0]
        return And(tuple(out)) if is_and else Or(tuple(out))
    return node
