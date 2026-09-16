"""RFC 8032 §7.1 test vectors against the vendored verifier. Only the PUBLIC key, message
and signature from the RFC appear here — never the secret keys — plus the negative cases
the RFC vectors do not cover (malleability, corruption)."""

import pytest

from fortressflag._ed25519 import L_ORDER, verify

# (public key, message, signature) — RFC 8032 §7.1 TEST 1, TEST 2, TEST 3 and SHA(abc).
_VECTORS: list[tuple[str, bytes, str]] = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        b"",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e"
        "39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        bytes.fromhex("72"),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f"
        "3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        bytes.fromhex("af82"),
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67"
        "f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        bytes.fromhex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba"
            "3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        ),
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfb"
        "c7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
]


@pytest.mark.parametrize(("pk", "msg", "sig"), _VECTORS, ids=["test1", "test2", "test3", "sha-abc"])
def test_rfc_8032_vectors_verify(pk: str, msg: bytes, sig: str) -> None:
    assert verify(bytes.fromhex(pk), msg, bytes.fromhex(sig)) is True


@pytest.mark.parametrize(("pk", "msg", "sig"), _VECTORS, ids=["test1", "test2", "test3", "sha-abc"])
def test_a_flipped_message_byte_fails(pk: str, msg: bytes, sig: str) -> None:
    altered = (bytes([msg[0] ^ 0x01]) + msg[1:]) if msg else b"\x00"
    assert verify(bytes.fromhex(pk), altered, bytes.fromhex(sig)) is False


@pytest.mark.parametrize(("pk", "msg", "sig"), _VECTORS, ids=["test1", "test2", "test3", "sha-abc"])
def test_a_flipped_signature_bit_fails(pk: str, msg: bytes, sig: str) -> None:
    raw = bytearray(bytes.fromhex(sig))
    raw[5] ^= 0x40  # inside R
    assert verify(bytes.fromhex(pk), msg, bytes(raw)) is False
    raw = bytearray(bytes.fromhex(sig))
    raw[40] ^= 0x01  # inside S
    assert verify(bytes.fromhex(pk), msg, bytes(raw)) is False


def test_s_plus_l_is_rejected_malleability() -> None:
    pk, msg, sig = _VECTORS[0]
    raw = bytes.fromhex(sig)
    s = int.from_bytes(raw[32:], "little")
    forged = raw[:32] + (s + L_ORDER).to_bytes(32, "little")
    # Same point equation would hold; the canonical-S rule is what refuses it.
    assert verify(bytes.fromhex(pk), msg, forged) is False


def test_wrong_lengths_and_undecompressable_points_fail_without_raising() -> None:
    pk, msg, sig = _VECTORS[0]
    assert verify(bytes.fromhex(pk)[:31], msg, bytes.fromhex(sig)) is False
    assert verify(bytes.fromhex(pk), msg, bytes.fromhex(sig)[:63]) is False
    assert verify(b"", b"", b"") is False
    # y = p - 1 with the sign bit set is not on the curve.
    not_a_point = bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    assert verify(not_a_point, msg, bytes.fromhex(sig)) is False
    assert verify(bytes.fromhex(pk), msg, not_a_point + bytes.fromhex(sig)[32:]) is False
