"""Verify-only Ed25519 (RFC 8032 §5.1), vendored so the SDK keeps zero runtime dependencies
(ADR-0020) and one code path on every interpreter (ADR-0025).

Pure Ed25519 — SHA-512 over ``R || A || M``, never the prehashed variant. Arithmetic is the
RFC's reference algorithm on Python ``int`` in extended twisted-Edwards coordinates. The
group equation checked is the cofactored one the RFC names first, ``[8][S]B = [8]R + [8][k]A``.
Rejected before any arithmetic: a signature or key that is not 32/64 bytes, ``S >= L``
(malleability), and a public key or ``R`` that does not decompress to a point.

A verification costs single-digit milliseconds in CPython (three scalar multiplications
on big ints; measured ~2 ms on a laptop, budget tens of ms on a slow host). Acceptable at
one ruleset per poll (a minute apart, floored at 30 s); this module is never on the
flag-read path.
"""

from __future__ import annotations

import hashlib
from typing import Final

_P: Final[int] = 2**255 - 19
#: The order of the base point's subgroup (the RFC's ``L``; ruff E741 forbids the letter).
L_ORDER: Final[int] = 2**252 + 27742317777372353535851937790883648493
_D: Final[int] = (-121665 * pow(121666, _P - 2, _P)) % _P
#: sqrt(-1) mod p, used by the decompression's second candidate.
_SQRT_M1: Final[int] = pow(2, (_P - 1) // 4, _P)

#: A point in extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z.
_Point = tuple[int, int, int, int]
_IDENTITY: Final[_Point] = (0, 1, 1, 0)

PUBLIC_KEY_SIZE: Final[int] = 32
SIGNATURE_SIZE: Final[int] = 64


def _point_add(p: _Point, q: _Point) -> _Point:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(scalar: int, point: _Point) -> _Point:
    result = _IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _point_equal(p: _Point, q: _Point) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    """RFC 8032 §5.1.3 steps 2-4: the x for a given y and sign bit, or None."""
    if y >= _P:
        return None
    y2 = y * y % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    x = u * pow(v, 3, _P) % _P * pow(u * pow(v, 7, _P) % _P, (_P - 5) // 8, _P) % _P
    vx2 = v * x * x % _P
    if vx2 == u:
        pass
    elif vx2 == (-u) % _P:
        x = x * _SQRT_M1 % _P
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


def _decompress(encoded: bytes) -> _Point | None:
    if len(encoded) != PUBLIC_KEY_SIZE:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _base_point() -> _Point:
    y = 4 * pow(5, _P - 2, _P) % _P
    x = _recover_x(y, 0)
    assert x is not None  # noqa: S101 - a constant of the curve, not input
    return (x, y, 1, x * y % _P)


_B: Final[_Point] = _base_point()


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff ``signature`` is a valid pure-Ed25519 signature of ``message`` under
    ``public_key``. Never raises on input of any shape."""
    if len(public_key) != PUBLIC_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    a_point = _decompress(public_key)
    if a_point is None:
        return False
    r_point = _decompress(signature[:32])
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L_ORDER:
        return False
    digest = hashlib.sha512(signature[:32] + public_key + message).digest()
    k = int.from_bytes(digest, "little") % L_ORDER
    lhs = _point_mul(8 * s, _B)
    rhs = _point_add(_point_mul(8, r_point), _point_mul(8 * k, a_point))
    return _point_equal(lhs, rhs)
