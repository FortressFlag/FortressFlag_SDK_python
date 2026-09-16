"""The wire envelope (server-contract-v1.md): the client envelope design, reused.

``sig`` is a detached Ed25519 signature over the payload's exact bytes (backend ADR-0025);
only a local development backend without signing keys omits it.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from ._ruleset import FlagConfig, parse_flag_config

#: The sv this SDK requests and accepts.
SUPPORTED_SERVER_CONTRACT_VERSION: Final[int] = 1

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

#: Date.parse-style leniency is fenced everywhere: the contract's timestamps are RFC 3339,
#: fractional seconds tolerated. fromisoformat (3.11+) accepts a superset (dates without
#: times, space separators), so the shape is gated first — a payload the Go SDK rejects
#: must not verify here.
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

_MISSING_SENTINEL: Final[object] = object()


def decode_base64url(s: str) -> bytes | None:
    """Decode UNPADDED base64url strictly, or return None.

    ``base64.urlsafe_b64decode`` demands the padding the wire never sends and tolerates
    some dirty input; the alphabet is validated first, any ``=`` in the input is refused,
    and padding is added only for the decode itself. A lenient decoder here accepts
    envelopes the sibling SDKs reject — contract drift in the lenient direction.
    """
    if s == "" or not _BASE64URL.match(s):
        return None
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class WireEnvelope:
    payload: str
    #: None means "absent or null" — legal only under SIGNATURE_DISABLED; "" is
    #: present-but-empty, which a required policy rejects as missing.
    sig: str | None


@dataclass(frozen=True, slots=True)
class RulesetPayload:
    """The decoded payload document."""

    sv: int
    tenant: str
    project: str
    environment: str
    issued_at: str
    expires_at: str
    flags: Mapping[str, FlagConfig]


@dataclass(frozen=True, slots=True)
class ParsedEnvelope:
    envelope: WireEnvelope
    payload_bytes: bytes


def parse_envelope(raw: bytes) -> ParsedEnvelope | None:
    """Split raw bytes into the envelope and its decoded payload bytes, or None.

    A body that is not an envelope is a rejection, never a crash (captive portals serve
    HTML with a 200; the transport treats the server as hostile). ``json.loads`` parses
    NaN/Infinity by default — refused via parse_constant: JSON cannot express them, so
    their presence is corruption or hostility.
    """
    parsed = _load_strict_json(raw)
    if not isinstance(parsed, dict):
        return None
    payload = parsed.get("payload")
    if not isinstance(payload, str) or payload == "":
        return None
    sig = parsed.get("sig")
    if sig is not None and not isinstance(sig, str):
        return None
    payload_bytes = decode_base64url(payload)
    if payload_bytes is None:
        return None
    return ParsedEnvelope(
        envelope=WireEnvelope(payload=payload, sig=sig), payload_bytes=payload_bytes
    )


def parse_payload(payload_bytes: bytes) -> RulesetPayload | None:
    """Decode the payload document, requiring the fields whose absence would make the
    binding checks meaningless.

    Unknown fields are ignored — additive server changes ride sv=1 (the contract's
    versioning rule), and the raw bytes are what the cache retains.

    Flag KINDS are validated here, and a payload carrying one this build does not know is
    rejected WHOLE — the client SDKs' union-violation posture, applied to configs: the
    contract makes a new kind an sv bump, so an unknown kind on sv=1 is corruption or
    hostility, and under wholesale snapshot overwrite an accepted half-broken payload
    would dislodge held values into fallbacks. Rejecting keeps the last verified state
    serving, which is the cascade's whole point. (Value-vs-kind mismatches inside rules
    stay per-flag fail-closed in the evaluator, the backend's own defensive posture.)
    """
    parsed = _load_strict_json(payload_bytes)
    if not isinstance(parsed, dict):
        return None
    sv = parsed.get("sv")
    environment = parsed.get("environment")
    issued_at = parsed.get("issuedAt")
    expires_at = parsed.get("expiresAt")
    if isinstance(sv, bool) or not isinstance(sv, int):
        return None
    if not isinstance(environment, str) or environment == "":
        return None
    if not isinstance(issued_at, str) or issued_at == "":
        return None
    if not isinstance(expires_at, str) or expires_at == "":
        return None
    flags_raw = parsed.get("flags", {})
    if not isinstance(flags_raw, dict):
        return None
    flags: dict[str, FlagConfig] = {}
    for flag_key, config_raw in flags_raw.items():
        if not isinstance(flag_key, str):
            return None
        config = parse_flag_config(config_raw)
        if config is None:
            return None
        if config.kind not in ("boolean", "string", "number"):
            return None
        flags[flag_key] = config
    tenant = parsed.get("tenant")
    project = parsed.get("project")
    return RulesetPayload(
        sv=sv,
        tenant=tenant if isinstance(tenant, str) else "",
        project=project if isinstance(project, str) else "",
        environment=environment,
        issued_at=issued_at,
        expires_at=expires_at,
        flags=flags,
    )


def parse_wire_time(s: str) -> float | None:
    """Parse the contract's RFC 3339 timestamps to a Unix timestamp, or None."""
    if not _RFC3339.match(s):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _reject_constant(_value: str) -> Any:
    raise ValueError("fortressflag: NaN/Infinity are not JSON")


def _load_strict_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError):
        return None
