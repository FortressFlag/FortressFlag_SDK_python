"""Local evaluation — the reason this SDK exists.

Founding §3: evaluation happens as close to the customer as possible. A byte-for-byte
behavioural PORT of the backend's clientapi evaluateValue walk via the Go SDK; the
implementations are pinned to each other by vectors/evaluation.json — a semantic difference
here is a wire-contract bug, never a local judgement call. No I/O, no logging, no
allocation beyond the walk — this sits on the customer's hot path.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._bucket import bucket
from ._ruleset import FlagCondition, FlagConfig, FlagRule, decode_value
from ._semver import compare_versions, parse_version

_SEMVER_OPERATORS = frozenset({"semver_eq", "semver_gt", "semver_gte", "semver_lt", "semver_lte"})


def evaluate_flag(
    config: FlagConfig,
    tags: Mapping[str, str],
    context_key: str,
    flag_key: str,
) -> tuple[Any, bool]:
    """Walk the rules in order; first match serves, else the default.

    Returns ``(value, ok)`` — a multivariate flag with no default variant and no matching
    rule answers ``(None, False)``: the caller's fallback serves. The per-rule semantics,
    exactly as the contract states them:

    - A rule matches when EVERY condition holds — AND within a rule, first-match-wins
      across rules. An EMPTY condition list holds vacuously (the terminal "everyone else"
      rule).
    - A condition whose tag key is absent from the context's tags does not hold; never an
      error. eq/neq are exact string comparison and contains is substring match (backend
      ADR-0023) — all case-sensitive, no trimming. The semver
      operators compare via parse_version; an unparseable value on EITHER side makes the
      condition not hold. An operator this build does not recognise does not hold — fail
      closed into the default (Founding §8.3).
    - The rollout gate: conditions held, now the percentage decides. The bucket is computed
      at most once per flag, only when a matching rule actually carries a gate, and a
      gated-out context falls THROUGH to later rules and the default — which is what makes
      "50% rule, then everyone-else rule" compose under first-match-wins. A gate of 0 is a
      real gate that matches nobody: presence is ``is not None``, never truthiness.
    - A rule whose serve value does not follow the flag's kind cannot be written through
      the management API; if one ever appears, fail closed past it rather than serve a
      guess.
    """
    context_bucket = -1
    for rule in config.rules:
        if not _rule_matches(rule, tags):
            continue
        if rule.rollout_percentage is not None:
            if context_bucket < 0:
                context_bucket = bucket(context_key, flag_key)
            if context_bucket >= rule.rollout_percentage:
                continue
        value, ok = decode_value(rule.serve, config.kind)
        if ok:
            return value, True
    return decode_value(config.default, config.kind)


def _rule_matches(rule: FlagRule, tags: Mapping[str, str]) -> bool:
    """AND the rule's conditions: every one must hold.

    Iterating an empty tuple runs zero times, which is exactly the vacuous truth the
    contract specifies.
    """
    for condition in rule.conditions:
        tag_value = tags.get(condition.tag_key)
        if tag_value is None:
            return False
        if not _condition_holds(condition, tag_value):
            return False
    return True


def _condition_holds(condition: FlagCondition, tag_value: str) -> bool:
    operator = condition.operator
    if operator == "eq":
        return tag_value == condition.value
    if operator == "neq":
        return tag_value != condition.value
    if operator == "contains":
        return condition.value in tag_value
    if operator in _SEMVER_OPERATORS:
        context = parse_version(tag_value)
        if context is None:
            return False
        target = parse_version(condition.value)
        if target is None:
            return False
        cmp = compare_versions(context, target)
        if operator == "semver_eq":
            return cmp == 0
        if operator == "semver_gt":
            return cmp > 0
        if operator == "semver_gte":
            return cmp >= 0
        if operator == "semver_lt":
            return cmp < 0
        return cmp <= 0  # semver_lte
    return False
