"""Shared test fixtures: the fixed clock and the payload/envelope builders. The key is
short and low-entropy on purpose (CLAUDE.md §3); the clock is fixed so expiry tests assert
instants, not races."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any

FIXTURE_NOW_S = datetime.fromisoformat("2026-08-21T10:15:00+00:00").timestamp()


def fixture_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "sv": 1,
        "tenant": "t",
        "project": "default",
        "environment": "dev",
        "issuedAt": "2026-08-21T10:00:00Z",
        "expiresAt": "2026-08-21T10:30:00Z",
        "flags": {
            "dark-mode": {
                "kind": "boolean",
                "default": False,
                "rules": [
                    {
                        "conditions": [{"tagKey": "cohort", "operator": "eq", "value": "beta"}],
                        "serve": True,
                    }
                ],
            },
            "checkout-cta": {"kind": "string", "default": "buy-now", "rules": []},
        },
    }
    for key, value in overrides.items():
        if value is None and key in ("issuedAt", "expiresAt", "environment"):
            del base[key]
        else:
            base[key] = value
    return base


def fixture_envelope(payload: dict[str, Any], sig: str | None = None) -> bytes:
    body: dict[str, Any] = {
        "payload": base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    }
    if sig is not None:
        body["sig"] = sig
    return json.dumps(body).encode()
