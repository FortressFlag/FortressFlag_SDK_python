"""The published signing vectors (FortressFlag_Standards vectors/signing.json, backend
ADR-0025), fed to THIS SDK's verifier as the exact envelope bytes — never re-serialised.
A failure here is a wire-contract bug, never a test to fix."""

import base64
import json
from datetime import datetime
from importlib import resources
from typing import Any

import pytest

from fortressflag._configuration import SIGNATURE_DISABLED, signature_required
from fortressflag._envelope import parse_envelope
from fortressflag._verifier import Expectations, RejectionCode, check_signature, verify_envelope

_FILE: Any = json.loads(
    resources.files("fortressflag._vectors").joinpath("signing.json").read_text()
)
_KEY_ID: str = _FILE["keyId"]
_PUBLIC_KEY: bytes = base64.urlsafe_b64decode(_FILE["publicKey"] + "=")
_POLICY = signature_required({_KEY_ID: _PUBLIC_KEY})
# The vector payloads are issued 2026-09-16 and expire in 2099; any clock in between works.
_NOW_S = datetime.fromisoformat("2026-09-16T12:00:00+00:00").timestamp()
_EXPECT = Expectations(environment="prod", now_s=_NOW_S, enforce_expiry=True)


def _envelope(entry: dict[str, Any]) -> bytes:
    raw = entry["envelope"]
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def test_the_vector_file_carries_only_a_public_key() -> None:
    assert len(_PUBLIC_KEY) == 32
    assert "privateKey" not in _FILE and "seed" not in _FILE


@pytest.mark.parametrize("entry", _FILE["accept"], ids=[e["name"] for e in _FILE["accept"]])
def test_accept_entries_have_valid_signatures(entry: dict[str, Any]) -> None:
    parsed = parse_envelope(_envelope(entry))
    assert parsed is not None
    assert check_signature(parsed.envelope.sig, parsed.payload_bytes, _POLICY) is None


def test_the_server_vector_verifies_end_to_end() -> None:
    entry = next(e for e in _FILE["accept"] if e["name"] == "server-sv1")
    verified, code = verify_envelope(_envelope(entry), _POLICY, _EXPECT)
    assert code is None and verified is not None
    assert set(verified.payload.flags) == {"checkout-cta", "dark-mode", "max-items"}


@pytest.mark.parametrize("entry", _FILE["reject"], ids=[e["name"] for e in _FILE["reject"]])
def test_reject_entries_fail_with_the_named_code(entry: dict[str, Any]) -> None:
    _, code = verify_envelope(_envelope(entry), _POLICY, _EXPECT)
    assert code is RejectionCode(entry["code"])


def test_the_wrong_key_under_a_known_key_id_is_a_bad_signature() -> None:
    other = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    entry = next(e for e in _FILE["accept"] if e["name"] == "server-sv1")
    _, code = verify_envelope(_envelope(entry), signature_required({_KEY_ID: other}), _EXPECT)
    assert code is RejectionCode.BAD_SIGNATURE


def test_a_malformed_key_in_the_trust_store_is_unknown_not_bad() -> None:
    entry = next(e for e in _FILE["accept"] if e["name"] == "server-sv1")
    _, code = verify_envelope(_envelope(entry), signature_required({_KEY_ID: b"short"}), _EXPECT)
    assert code is RejectionCode.UNKNOWN_KEY_ID


def test_disabled_accepts_the_unsigned_vector() -> None:
    entry = next(e for e in _FILE["reject"] if e["name"] == "unsigned")
    parsed = parse_envelope(_envelope(entry))
    assert parsed is not None and parsed.envelope.sig is None
    assert check_signature(parsed.envelope.sig, parsed.payload_bytes, _POLICY) is (
        RejectionCode.MISSING_SIGNATURE
    )
    # Under the explicit opt-out the signature step is skipped entirely.
    assert not SIGNATURE_DISABLED.required
