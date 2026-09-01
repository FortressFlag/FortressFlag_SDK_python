"""How long to wait before the next poll — a port of the sibling SDKs' backoff, reasoning
included, because the second job matters MORE at server scale.

The obvious job is to stop a process hammering a failing backend. The less obvious job is
DE-SYNCHRONISATION: without jitter, every process in a fleet that started polling at the
same moment — which, after an outage, is all of them — retries in lockstep, and the backend
that just came back up is knocked over by its own clients. Jitter on the success path
matters as much as on the failure path: a 100-process deployment restarted by an
orchestrator polls as 100 spikes a minute forever unless the routine interval is jittered
too.

Randomness is injected so the bounds can be asserted in tests instead of hoped for.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

RandomInRange = Callable[[float, float], float]

#: The ceiling: half an hour. A process that has been failing for hours is almost certainly
#: firewalled or misconfigured, and there is nothing to gain from asking more often — the
#: snapshot is already answering every call.
_BACKOFF_CAP_S: Final[float] = 1800.0
#: The delay after the first failure. Doubles from here.
_BACKOFF_BASE_S: Final[float] = 2.0
#: Spreads every delay ±20%.
_BACKOFF_JITTER_FRACTION: Final[float] = 0.2


def retry_delay_s(consecutive_failures: int, random_in_range: RandomInRange) -> float:
    """The wait after consecutive_failures failures in a row."""
    if consecutive_failures <= 0:
        return 0.0
    # Exponent capped before the power so a long-offline process cannot overflow the
    # multiplier on its ten-thousandth failed attempt.
    exponent = min(consecutive_failures - 1, 32)
    raw = min(_BACKOFF_BASE_S * (2.0**exponent), _BACKOFF_CAP_S)
    return _jittered(raw, random_in_range)


def poll_delay_s(interval_s: float, random_in_range: RandomInRange) -> float:
    """The wait before the next routine poll — jittered, see the module docstring."""
    return _jittered(interval_s, random_in_range)


def retry_delay_with_server_hint_s(
    retry_after_seconds: int, consecutive_failures: int, random_in_range: RandomInRange
) -> float:
    """Obey a server that told us when to come back — but never past the cap.

    A hostile or misconfigured Retry-After of a year must not silently disable flag
    updates for a process until it restarts.
    """
    if retry_after_seconds <= 0:
        return retry_delay_s(consecutive_failures, random_in_range)
    return min(float(retry_after_seconds), _BACKOFF_CAP_S)


def _jittered(seconds: float, random_in_range: RandomInRange) -> float:
    spread = seconds * _BACKOFF_JITTER_FRACTION
    return random_in_range(seconds - spread, seconds + spread)
