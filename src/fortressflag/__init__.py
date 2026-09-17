"""The public surface of the FortressFlag Python server SDK.

Everything the SDK exports is enumerated in ``__all__`` (the sibling SDKs' one-file-surface
rule); everything else is underscore-internal. Backward compatibility of everything here is
sacred (Founding §8.3).

``create()`` is the ONE place the SDK raises (a malformed key, before anything serves).
After that: ``start()`` never raises, getters never raise, ``close()`` is idempotent, and
every failure resolves to the caller's fallback with the reason on ``diagnostics()``.
"""

from ._client import Client, Context, Diagnostics, ResolutionCounters, StartOutcome
from ._configuration import (
    FORTRESSFLAG_PRODUCTION,
    SIGNATURE_DISABLED,
    Configuration,
    MalformedKeyError,
    SignaturePolicy,
    resolve_configuration,
    signature_required,
)
from ._transport import Transport

__all__ = [
    "FORTRESSFLAG_PRODUCTION",
    "SIGNATURE_DISABLED",
    "Client",
    "Configuration",
    "Context",
    "Diagnostics",
    "MalformedKeyError",
    "ResolutionCounters",
    "SignaturePolicy",
    "StartOutcome",
    "create",
    "signature_required",
]


def create(configuration: Configuration) -> Client:
    """Validate the configuration and return a Client. Raises MalformedKeyError — the one
    raise."""
    resolved = resolve_configuration(configuration)
    return Client(resolved, Transport(resolved))
