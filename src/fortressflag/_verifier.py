"""Envelope verification: is this payload from FortressFlag (signature policy), about us
(environment), and now (issuedAt/expiresAt)?

A rejection is never fatal: it means "keep serving the last verified snapshot" (Founding
§8.4). Rejections are enumerated in this much detail because "flags stopped updating" is
otherwise one of the hardest things to debug in a customer's service, and the answer should
be one diagnostics() read.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Final

from . import _ed25519
from ._configuration import SignaturePolicy
from ._envelope import (
    SUPPORTED_SERVER_CONTRACT_VERSION,
    RulesetPayload,
    decode_base64url,
    parse_envelope,
    parse_payload,
    parse_wire_time,
)


class RejectionCode(enum.StrEnum):
    """Why an envelope was not accepted."""

    MALFORMED_ENVELOPE = "malformedEnvelope"
    MISSING_SIGNATURE = "missingSignature"
    MALFORMED_SIGNATURE = "malformedSignature"
    UNSUPPORTED_SIGNATURE_ALGORITHM = "unsupportedSignatureAlgorithm"
    UNKNOWN_KEY_ID = "unknownKeyId"
    BAD_SIGNATURE = "badSignature"
    MALFORMED_PAYLOAD = "malformedPayload"
    UNSUPPORTED_CONTRACT_VERSION = "unsupportedContractVersion"
    ENVIRONMENT_MISMATCH = "environmentMismatch"
    EXPIRED = "expired"
    ISSUED_IN_THE_FUTURE = "issuedInTheFuture"


@dataclass(frozen=True, slots=True)
class VerifiedEnvelope:
    """An envelope that passed every check, kept alongside the exact bytes it arrived as.

    ``raw`` is retained so the cache stores what was (or will one day be) signed rather
    than a re-serialisation of what we parsed — re-serialising would silently strip any
    field a future server adds and break the signature on reload (the web verifier's rule,
    ported).
    """

    raw: bytes
    payload: RulesetPayload


@dataclass(frozen=True, slots=True)
class Expectations:
    """What the payload must claim to be, for it to be about us.

    ``enforce_expiry``: TRUE for a live response, FALSE when loading the cache_path file —
    and that asymmetry is the single most load-bearing rule in this SDK. On a live
    response, expiry is the replay window: without it, anyone who captured a valid
    response could serve it back forever, pinning a fleet to old flag values. On a cache
    load it must NOT apply: the last verified snapshot is the primary fallback, and a
    service that restarts after a long outage keeps evaluating with what it last saw.
    Enforcing expiry there would silently revert every flag to caller defaults after any
    30-minute outage plus one restart — turning an outage into a feature regression, which
    is precisely the failure the cascade exists to prevent. Expiry governs freshness, not
    validity.
    """

    environment: str
    now_s: float
    enforce_expiry: bool


#: Forgives a wrong server-or-host clock. Machines drift; a host an hour fast should not
#: lose flag updates — but 300 s is the ceiling on how far issuedAt may sit in the future
#: before the payload is refused.
_CLOCK_SKEW_TOLERANCE_S: Final[float] = 300.0


def verify_envelope(
    raw: bytes, policy: SignaturePolicy, expect: Expectations
) -> tuple[VerifiedEnvelope | None, RejectionCode | None]:
    """Run every check in the contract's order and report the outcome."""
    parsed = parse_envelope(raw)
    if parsed is None:
        return None, RejectionCode.MALFORMED_ENVELOPE

    if policy.required:
        code = check_signature(parsed.envelope.sig, parsed.payload_bytes, policy)
        if code is not None:
            return None, code

    payload = parse_payload(parsed.payload_bytes)
    if payload is None:
        return None, RejectionCode.MALFORMED_PAYLOAD

    if payload.sv != SUPPORTED_SERVER_CONTRACT_VERSION:
        # A version this build does not speak might mean anything; refusing to guess is
        # the contract's own instruction.
        return None, RejectionCode.UNSUPPORTED_CONTRACT_VERSION
    if payload.environment != expect.environment:
        # A production payload replayed at a dev process (or vice versa) is refused even
        # though the key, not the payload, chose the scope: the two claims must agree.
        return None, RejectionCode.ENVIRONMENT_MISMATCH

    issued_at = parse_wire_time(payload.issued_at)
    if issued_at is None:
        return None, RejectionCode.MALFORMED_PAYLOAD
    expires_at = parse_wire_time(payload.expires_at)
    if expires_at is None:
        return None, RejectionCode.MALFORMED_PAYLOAD
    if issued_at - expect.now_s > _CLOCK_SKEW_TOLERANCE_S:
        return None, RejectionCode.ISSUED_IN_THE_FUTURE
    if expect.enforce_expiry and expect.now_s - expires_at > _CLOCK_SKEW_TOLERANCE_S:
        return None, RejectionCode.EXPIRED

    return VerifiedEnvelope(raw=raw, payload=payload), None


def check_signature(
    sig: str | None, payload_bytes: bytes, policy: SignaturePolicy
) -> RejectionCode | None:
    """``ed25519:<keyID>:<unpadded base64url>`` over ``payload_bytes`` exactly as transmitted
    (backend ADR-0025) — never a re-serialisation, never a subset of fields."""
    if sig is None or sig == "":
        return RejectionCode.MISSING_SIGNATURE
    # Split at the first two colons: the SIGNATURE may contain extra colons, the key ID
    # never can — the backend refuses a key ID with one (contract-v1 §Signing keys).
    first = sig.find(":")
    second = sig.find(":", first + 1) if first >= 0 else -1
    if first < 0 or second < 0:
        return RejectionCode.MALFORMED_SIGNATURE
    algorithm = sig[:first]
    key_id = sig[first + 1 : second]
    signature = sig[second + 1 :]
    if algorithm != "ed25519":
        return RejectionCode.UNSUPPORTED_SIGNATURE_ALGORITHM
    if signature == "" or decode_base64url(signature) is None:
        return RejectionCode.MALFORMED_SIGNATURE
    if key_id not in policy.trusted_keys:
        return RejectionCode.UNKNOWN_KEY_ID
    public_key = policy.trusted_keys[key_id]
    if len(public_key) != _ed25519.PUBLIC_KEY_SIZE:
        # A malformed key in our own trust store: "cannot verify with this key", so one
        # bad entry does not disable a rotation set (the iOS verifier's rule).
        return RejectionCode.UNKNOWN_KEY_ID
    raw_signature = decode_base64url(signature)
    if raw_signature is None or not _ed25519.verify(public_key, payload_bytes, raw_signature):
        return RejectionCode.BAD_SIGNATURE
    return None
