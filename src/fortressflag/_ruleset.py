"""The ruleset payload types, in the server export's wire shape (server-contract-v1.md).

These are this package's own types, decoded from the wire — a PORT of the backend's
clientapi rule types via the Go SDK, never a share (the port-don't-share doctrine: the
components must be free to diverge, and nothing management-side can silently ride into this
decoder). Underscore-internal: the wire shape is not public API.

``json.loads`` hands back an ABSENT key as a missing dict entry and an explicit ``null`` as
``None`` — and absent, ``None`` and ``False`` must stay three different things (a boolean
flag's ``False`` default is a value; a multivariate flag with no default variant has the
field omitted). The ``MISSING`` sentinel keeps them apart; ``decode_value`` treats absent
and ``None`` identically as no-value and never collapses either into ``False``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Final

#: The sentinel for "the wire omitted this field" — distinct from JSON null (None).
MISSING: Final[object] = object()

_NO_VALUE: Final[tuple[None, bool]] = (None, False)


@dataclass(frozen=True, slots=True)
class FlagCondition:
    """One ANDed test inside a rule. Position is implicit in list order."""

    tag_key: str
    operator: str
    value: str


@dataclass(frozen=True, slots=True)
class FlagRule:
    """One targeting rule: ordered ANDed conditions, the served value, the optional gate.

    ``rollout_percentage`` is ``None`` for no gate; ``0`` is a REAL gate that matches
    nobody (``rollout-zero-matches-nobody`` is a published vector) — presence tests are
    ``is not None``, never truthiness.
    """

    conditions: tuple[FlagCondition, ...]
    serve: Any
    rollout_percentage: int | None


@dataclass(frozen=True, slots=True)
class FlagConfig:
    """Everything the export says about one flag. ``default`` may be ``MISSING``."""

    kind: str
    default: Any = MISSING
    rules: tuple[FlagRule, ...] = field(default_factory=tuple)


def decode_value(raw: Any, kind: str) -> tuple[Any, bool]:
    """Decode a raw wire value by the flag's kind, reporting whether a value was present.

    Absent (``MISSING``) and an explicit ``null`` (``None``) are treated identically as
    no-value: the contract omits the field for a multivariate flag with no default
    variant, and a decoder that raised on a null would violate fail-safe. A value that
    does not follow the kind, or a kind this build does not know, is no-value too: fail
    closed into the caller's fallback rather than serve a guess (Founding §8.3).

    ``bool`` is checked BEFORE the number path and excluded from it —
    ``isinstance(True, int)`` is ``True``, and a number check written naively would accept
    JSON ``true`` as ``1``. Numbers must be finite: JSON cannot express NaN/Infinity, so a
    non-finite float here is a hostile decode.
    """
    if raw is MISSING or raw is None:
        return _NO_VALUE
    if kind == "boolean":
        return (raw, True) if isinstance(raw, bool) else _NO_VALUE
    if kind == "string":
        return (raw, True) if isinstance(raw, str) else _NO_VALUE
    if kind == "number":
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return _NO_VALUE
        value = float(raw)
        return (value, True) if math.isfinite(value) else _NO_VALUE
    return _NO_VALUE


def parse_flag_config(raw: Any) -> FlagConfig | None:
    """Build a FlagConfig from decoded JSON, or None when the shape is not a flag config.

    Kind validation happens in the verifier (unknown kind rejects the WHOLE payload); this
    parser only refuses shapes that cannot be walked at all.
    """
    if not isinstance(raw, dict):
        return None
    kind = raw.get("kind")
    if not isinstance(kind, str):
        return None
    rules_raw = raw.get("rules")
    if not isinstance(rules_raw, list):
        return None
    rules: list[FlagRule] = []
    for rule_raw in rules_raw:
        if not isinstance(rule_raw, dict):
            return None
        conditions_raw = rule_raw.get("conditions")
        if not isinstance(conditions_raw, list):
            return None
        conditions: list[FlagCondition] = []
        for condition_raw in conditions_raw:
            if not isinstance(condition_raw, dict):
                return None
            tag_key = condition_raw.get("tagKey")
            operator = condition_raw.get("operator")
            value = condition_raw.get("value")
            if not isinstance(tag_key, str) or not isinstance(operator, str):
                return None
            if not isinstance(value, str):
                return None
            conditions.append(FlagCondition(tag_key=tag_key, operator=operator, value=value))
        rollout = rule_raw.get("rolloutPercentage")
        if rollout is not None and (isinstance(rollout, bool) or not isinstance(rollout, int)):
            return None
        rules.append(
            FlagRule(
                conditions=tuple(conditions),
                serve=rule_raw.get("serve", MISSING),
                rollout_percentage=rollout,
            )
        )
    return FlagConfig(
        kind=kind,
        default=raw.get("default", MISSING),
        rules=tuple(rules),
    )
