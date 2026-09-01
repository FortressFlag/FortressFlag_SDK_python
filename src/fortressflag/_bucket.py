"""Places one context in [0, 100) for one flag's percentage rollout.

ADR-0008, published in contract-v2.md and pinned by vectors/buckets.json:

    uint64_be(SHA-256(contextKey + ":" + flagKey)[0..8]) mod 100

The context key is EXACTLY the opaque identifier string the caller gave this SDK — a user
id, a session id, the customer's choice — never validated, trimmed or normalised: the
backend hashes a device ID the same way, and any deviation from "hash exactly the bytes
given" flips cohorts between components evaluating for the same person. The hash input is
the UTF-8 bytes of the concatenation. Nothing is stored: a bucket is recomputed per
evaluation. The ":" + flagKey suffix makes buckets per-flag (a 10% rollout is not always
the same unlucky 10%) and sticky.
"""

from __future__ import annotations

import hashlib


def bucket(context_key: str, flag_key: str) -> int:
    digest = hashlib.sha256(f"{context_key}:{flag_key}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % 100
