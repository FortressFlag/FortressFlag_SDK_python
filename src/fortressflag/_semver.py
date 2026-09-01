"""Dotted-numeric version comparison for the semver_* operators.

A PORT of the backend's internal/semver, whose package comment is the specification. It is
deliberately NOT Semantic Versioning 2.0.0: targeting needs "is this version at least
2.0?", and the semantics are a contract shared with every SDK (contract-v1.md, ADR-0004;
pinned by vectors/evaluation.json):

- Split on '.'; compare numeric components left to right.
- A missing component is 0: "2.0" == "2.0.0".
- Components must be non-negative base-10 integers. Anything else — "2.0-beta", "v2", "" —
  does not parse. What non-parsing MEANS belongs to the caller: a context value that does
  not parse makes the condition not hold (never an error).
"""

from __future__ import annotations

from typing import Final

#: Bounds one component's length. Ten digits already exceed int32; a longer run of digits
#: is not a version, and refusing it keeps a hostile tag value from turning the comparison
#: into big-integer work.
_MAX_VERSION_COMPONENT_DIGITS: Final[int] = 10


def parse_version(s: str) -> tuple[int, ...] | None:
    """Report whether s is a dotted non-negative-integer version, parsed.

    Returns None rather than raising: the caller's question is "is this comparable?", and
    evaluation may never fail over the answer.
    """
    if s == "":
        return None
    components: list[int] = []
    for part in s.split("."):
        if part == "" or len(part) > _MAX_VERSION_COMPONENT_DIGITS:
            return None
        if not part.isascii() or not part.isdigit():
            return None
        components.append(int(part))
    return tuple(components)


def compare_versions(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Return -1, 0 or 1 as a is less than, equal to, or greater than b.

    Missing components read as 0, which is what makes "2.0" equal "2.0.0" — the property
    the contract documents by example, and the one a naive length comparison would get
    wrong.
    """
    for i in range(max(len(a), len(b))):
        av = a[i] if i < len(a) else 0
        bv = b[i] if i < len(b) else 0
        if av < bv:
            return -1
        if av > bv:
            return 1
    return 0
