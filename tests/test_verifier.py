import pytest
from tests.support import FIXTURE_NOW_S, fixture_envelope, fixture_payload

from fortressflag._configuration import SIGNATURE_DISABLED, signature_required
from fortressflag._envelope import decode_base64url, parse_wire_time
from fortressflag._verifier import Expectations, RejectionCode, verify_envelope

LIVE = Expectations(environment="dev", now_s=FIXTURE_NOW_S, enforce_expiry=True)


def test_a_good_live_envelope_verifies_and_retains_its_raw_bytes() -> None:
    raw = fixture_envelope(fixture_payload())
    envelope, code = verify_envelope(raw, SIGNATURE_DISABLED, LIVE)
    assert code is None and envelope is not None
    assert envelope.raw == raw
    assert set(envelope.payload.flags) == {"dark-mode", "checkout-cta"}


@pytest.mark.parametrize("raw", [b"", b"{", b"null", b"<html>portal</html>", b'{"payload":""}'])
def test_bodies_that_are_not_envelopes_reject(raw: bytes) -> None:
    envelope, code = verify_envelope(raw, SIGNATURE_DISABLED, LIVE)
    assert envelope is None and code is RejectionCode.MALFORMED_ENVELOPE


def test_a_padded_base64url_payload_is_refused() -> None:
    import base64 as b64
    import json as j

    padded = b64.urlsafe_b64encode(j.dumps(fixture_payload()).encode()).decode()  # keeps "="
    assert padded.endswith("=")
    raw = j.dumps({"payload": padded}).encode()
    envelope, _code = verify_envelope(raw, SIGNATURE_DISABLED, LIVE)
    assert envelope is None


def test_nan_in_a_payload_is_refused_json_loads_leniency_fenced() -> None:
    import base64 as b64

    hostile = (
        b'{"sv": 1, "environment": "dev", "issuedAt": "x", "expiresAt": "y",'
        b' "flags": {"f": {"kind": "number", "default": NaN, "rules": []}}}'
    )
    raw = b'{"payload": "' + b64.urlsafe_b64encode(hostile).rstrip(b"=") + b'"}'
    envelope, code = verify_envelope(raw, SIGNATURE_DISABLED, LIVE)
    assert envelope is None and code is RejectionCode.MALFORMED_PAYLOAD


def test_sv_other_than_1_rejects_whole() -> None:
    _, code = verify_envelope(fixture_envelope(fixture_payload(sv=99)), SIGNATURE_DISABLED, LIVE)
    assert code is RejectionCode.UNSUPPORTED_CONTRACT_VERSION


def test_environment_mismatch_rejects() -> None:
    _, code = verify_envelope(
        fixture_envelope(fixture_payload(environment="prod")), SIGNATURE_DISABLED, LIVE
    )
    assert code is RejectionCode.ENVIRONMENT_MISMATCH


def test_an_unknown_flag_kind_rejects_the_whole_payload() -> None:
    flags = {
        "ok": {"kind": "boolean", "default": False, "rules": []},
        "bad": {"kind": "datetime", "rules": []},
    }
    _, code = verify_envelope(
        fixture_envelope(fixture_payload(flags=flags)), SIGNATURE_DISABLED, LIVE
    )
    assert code is RejectionCode.MALFORMED_PAYLOAD


def test_the_expiry_asymmetry() -> None:
    stale = fixture_envelope(
        fixture_payload(issuedAt="2026-08-21T08:00:00Z", expiresAt="2026-08-21T08:30:00Z")
    )
    _, live_code = verify_envelope(stale, SIGNATURE_DISABLED, LIVE)
    assert live_code is RejectionCode.EXPIRED
    cache_env, cache_code = verify_envelope(
        stale,
        SIGNATURE_DISABLED,
        Expectations(environment="dev", now_s=FIXTURE_NOW_S, enforce_expiry=False),
    )
    assert cache_code is None and cache_env is not None  # freshness, not validity


def test_issued_in_the_future_beyond_skew_rejects_within_skew_verifies() -> None:
    _, far = verify_envelope(
        fixture_envelope(fixture_payload(issuedAt="2026-08-21T12:00:00Z")),
        SIGNATURE_DISABLED,
        LIVE,
    )
    assert far is RejectionCode.ISSUED_IN_THE_FUTURE
    near, _ = verify_envelope(
        fixture_envelope(fixture_payload(issuedAt="2026-08-21T10:18:00Z")),
        SIGNATURE_DISABLED,
        LIVE,
    )
    assert near is not None


def test_non_rfc3339_timestamps_reject() -> None:
    _, code = verify_envelope(
        fixture_envelope(fixture_payload(issuedAt="Aug 21 2026")), SIGNATURE_DISABLED, LIVE
    )
    assert code is RejectionCode.MALFORMED_PAYLOAD


@pytest.mark.parametrize(
    ("sig", "expected"),
    [
        (None, RejectionCode.MISSING_SIGNATURE),
        ("", RejectionCode.MISSING_SIGNATURE),
        ("garbage", RejectionCode.MALFORMED_SIGNATURE),
        ("ed25519:AAAA", RejectionCode.MALFORMED_SIGNATURE),
        ("p256:k1:AAAA", RejectionCode.UNSUPPORTED_SIGNATURE_ALGORITHM),
        ("ed25519:unknown:AAAA", RejectionCode.UNKNOWN_KEY_ID),
        # Well-formed, known key, three bytes of "signature" — the primitive refuses it.
        ("ed25519:k1:AAAA", RejectionCode.BAD_SIGNATURE),
    ],
)
def test_signature_shapes_reject_fail_closed(sig: str | None, expected: RejectionCode) -> None:
    policy = signature_required({"k1": bytes(32)})
    _, code = verify_envelope(fixture_envelope(fixture_payload(), sig=sig), policy, LIVE)
    assert code is expected


def test_decode_base64url_strictness() -> None:
    assert decode_base64url("aGk=") is None
    assert decode_base64url("a Gk") is None
    assert decode_base64url("") is None
    assert decode_base64url("aGk") == b"hi"


def test_parse_wire_time_shapes() -> None:
    assert parse_wire_time("2026-08-21T10:00:00Z") is not None
    assert parse_wire_time("2026-08-21T10:00:00.123Z") is not None
    assert parse_wire_time("2026-08-21T10:00:00+02:00") is not None
    assert parse_wire_time("2026-08-21") is None
    assert parse_wire_time("2026-08-21 10:00:00") is None
    assert parse_wire_time("Aug 21 2026") is None
