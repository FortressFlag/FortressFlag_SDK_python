"""Configuration and the key rules.

The ffs_ server key IS A GENUINE SECRET (server-contract-v1, ADR-0015): the SDK holds it in
memory, sends it only on the Authorization header, and the only form of it that may ever
reach a log line is ``key_prefix``'s six-character prefix.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

_DEFAULT_BASE_URL: Final[str] = "https://edge.fortressflag.com"
#: The contract's floor. Faster is volunteering to be rate-limited for unchanged values.
_MINIMUM_POLL_INTERVAL_S: Final[float] = 30.0
_DEFAULT_POLL_INTERVAL_S: Final[float] = 60.0
_DEFAULT_HTTP_TIMEOUT_S: Final[float] = 10.0

#: Six characters of the random part: enough to tell two keys apart in a log line, far too
#: few to guess the rest (the backend's serverkey.PrefixOf rule).
_KEY_PREFIX_VISIBLE_CHARS: Final[int] = 6

#: The server's environments_key_format CHECK: 2-32 chars, lowercase letters, digits and
#: hyphens, starting and ending with a letter or digit.
_ENVIRONMENT_KEY = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")


class MalformedKeyError(ValueError):
    """The configured value is not shaped like an ffs_ server key.

    Raised by ``create`` — the ONE place this SDK raises, at construction, before the
    customer's process serves anything (Founding §8.1). The message deliberately never
    echoes the configured value: a mistyped secret pasted into the wrong field must not
    land in an exception string that lands in a log.
    """

    def __init__(self) -> None:
        super().__init__("fortressflag: key is not of the form ffs_<environment>_<secret>")


@dataclass(frozen=True, slots=True)
class SignaturePolicy:
    """How the SDK treats the envelope's signature. Use the module helpers, not this
    class directly."""

    required: bool = False
    trusted_keys: Mapping[str, bytes] = field(default_factory=dict)


#: Accepts unsigned envelopes. The explicit opt-out for a local development backend that
#: runs without ``FF_SIGNING_*`` (ADR-0025) — a named, greppable value rather than a silent
#: fallback, so "why is this not verifying?" has an answer in the customer's source. Never
#: the default.
SIGNATURE_DISABLED: Final[SignaturePolicy] = SignaturePolicy()

#: The raw 32-byte Ed25519 public keys FortressFlag signs PRODUCTION rulesets with, by key
#: ID (ADR-0025; also published on the docs page ``concepts/payload-signing``). Rotation
#: adds key N+1 here before the backend switches to it. Staging signs with its own key,
#: never listed here: pass it to ``signature_required`` explicitly.
#: ADR-0025, minted 2026-09-16: base64url EaEF8MHNu3onHxemTg3-OcrKrq7ODsZIVEp-IVV2ojg
FORTRESSFLAG_PRODUCTION: Final[Mapping[str, bytes]] = MappingProxyType(
    {
        "prod-2026-09-k1": bytes.fromhex(
            "11a105f0c1cdbb7a271f17a64e0dfe39cacaaeaece0ec648544a7e215576a238"
        ),
    }
)


def signature_required(trusted_keys: Mapping[str, bytes]) -> SignaturePolicy:
    """Reject every envelope whose signature does not verify against trusted_keys.

    Pure Ed25519 over the exact payload bytes (backend ADR-0025). Rejection is never
    fatal — the SDK keeps serving its last verified snapshot. The mapping is copied and
    frozen.
    """
    return SignaturePolicy(
        required=True,
        trusted_keys=MappingProxyType({key_id: bytes(key) for key_id, key in trusted_keys.items()}),
    )


@dataclass(frozen=True, slots=True)
class Configuration:
    """Everything the SDK needs to run. Handed to ``create``; treated as immutable.

    ``key`` is the ffs_ server key — a genuine secret: store it in an environment variable
    or a secret manager, never in code, never in a repository, never in a log.
    ``poll_interval_s`` defaults to 60 (one request per minute per process, so a kill
    switch reaches a fleet within a minute), floored at the contract's 30, jittered ±20%.
    ``cache_path`` opts in to the durable cache: unset means in-memory only — where a
    server process may write is the operator's call, and this SDK writes nothing unasked
    (ADR-0016). The file holds only the ruleset envelope, never the key and never any
    evaluation context. ``http_timeout_s`` is short on purpose: a slow ruleset fetch must
    never become the customer's problem — the snapshot keeps answering. ``signature``
    defaults to required-with-production: every envelope must carry a signature that
    verifies against ``FORTRESSFLAG_PRODUCTION`` (fail closed, ADR-0025). Against a local
    backend without signing keys pass ``SIGNATURE_DISABLED`` explicitly.
    """

    key: str
    base_url: str = _DEFAULT_BASE_URL
    poll_interval_s: float = _DEFAULT_POLL_INTERVAL_S
    cache_path: str = ""
    signature: SignaturePolicy = signature_required(FORTRESSFLAG_PRODUCTION)
    http_timeout_s: float = _DEFAULT_HTTP_TIMEOUT_S


def parse_key(raw: str) -> str | None:
    """Validate the configured key's shape and return the environment it claims, or None.

    ``str.split("_", 2)`` IS correct in Python — maxsplit keeps the remainder, unlike
    JavaScript's truncating limit — but the underscore comment rides along a fifth time
    because the bug it prevents is identical everywhere: the secret is base64url, whose
    alphabet includes ``_``. Any parse that splits without keeping the remainder rejects
    roughly three keys in four, silently, fleet-wide, intermittently — and the happy-path
    key tested by hand would not have contained an underscore. The test suite pins a key
    with underscores in its secret.
    """
    parts = raw.split("_", 2)
    if len(parts) != 3 or parts[0] != "ffs" or parts[2] == "":
        return None
    environment = parts[1]
    if not _ENVIRONMENT_KEY.match(environment) or len(environment) < 2:
        return None
    return environment


def key_prefix(raw: str) -> str:
    """The non-secret leading part of the key — THE ONLY FORM OF A SERVER KEY THAT MAY
    EVER BE LOGGED (ADR-0015, ported). Empty for a malformed key."""
    environment = parse_key(raw)
    if environment is None:
        return ""
    head = len("ffs_") + len(environment) + 1
    if len(raw) < head + _KEY_PREFIX_VISIBLE_CHARS:
        return ""
    return raw[: head + _KEY_PREFIX_VISIBLE_CHARS]


@dataclass(frozen=True, slots=True)
class ResolvedConfiguration:
    """Configuration with every default applied and the key parsed — what the SDK runs on."""

    key: str
    environment: str
    base_url: str
    poll_interval_s: float
    cache_path: str
    signature: SignaturePolicy
    http_timeout_s: float


def resolve_configuration(configuration: Configuration) -> ResolvedConfiguration:
    """Validate and apply defaults. The one raise path in the SDK."""
    environment = parse_key(configuration.key)
    if environment is None:
        raise MalformedKeyError()
    base_url = configuration.base_url.rstrip("/") or _DEFAULT_BASE_URL
    poll_interval_s = max(configuration.poll_interval_s, _MINIMUM_POLL_INTERVAL_S)
    http_timeout_s = (
        configuration.http_timeout_s
        if configuration.http_timeout_s > 0
        else _DEFAULT_HTTP_TIMEOUT_S
    )
    return ResolvedConfiguration(
        key=configuration.key,
        environment=environment,
        base_url=base_url,
        poll_interval_s=poll_interval_s,
        cache_path=configuration.cache_path,
        signature=configuration.signature,
        http_timeout_s=http_timeout_s,
    )
