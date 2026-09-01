"""The client core: one daemon poller thread feeding a snapshot the getters read lock-free.

After ``create``, nothing in here raises to the caller or exits the process — every failure
becomes backoff plus a diagnostics note while the last snapshot keeps answering (Founding
§8.1/§8.4).

The concurrency model (CLAUDE.md §7): the snapshot is published by a single attribute
assignment — atomic under the GIL, a plain reference swap under free-threading — and
getters read it ONCE into a local and evaluate against that, never twice. Mutable
diagnostic state sits behind one lock the evaluation path never takes. Do not add a lock
to the read path "for safety" — the lock-free read IS the design (Go's atomic.Pointer,
translated).
"""

from __future__ import annotations

import random as _random
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ._backoff import RandomInRange, poll_delay_s, retry_delay_s, retry_delay_with_server_hint_s
from ._cache import FileCache
from ._configuration import ResolvedConfiguration
from ._envelope import parse_wire_time
from ._evaluate import evaluate_flag
from ._ruleset import FlagConfig
from ._transport import FetchKind, FetchOutcome, Transport
from ._verifier import Expectations, RejectionCode, VerifiedEnvelope, verify_envelope


class StartOutcome(StrEnum):
    """What start() reports. Never an exception."""

    READY = "ready"
    CACHE_ONLY = "cache-only"
    TIMED_OUT = "timed-out-serving-defaults"


@dataclass(frozen=True, slots=True)
class Context:
    """One evaluation's context: the opaque identifier the bucket hashes, plus tags."""

    key: str
    tags: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ResolutionCounters:
    served: int
    fallback_no_snapshot: int
    fallback_unknown_flag: int
    fallback_kind_mismatch: int
    fallback_no_value: int


@dataclass(frozen=True, slots=True)
class Diagnostics:
    """The one-line answer to "why are flags not updating?".

    Contains no secrets — the key appears in no form, not even its prefix.
    """

    last_fetch_at: float | None
    last_fetch_status: str
    last_rejection: str
    etag: str
    consecutive_failures: int
    snapshot_issued_at: float | None
    snapshot_source: str  # "network" | "cache" | ""
    flag_count: int
    cache_state: str
    resolutions: ResolutionCounters


@dataclass(frozen=True, slots=True)
class _Snapshot:
    flags: Mapping[str, FlagConfig]
    issued_at: float | None
    from_cache: bool


def _snapshot_of(envelope: VerifiedEnvelope, from_cache: bool) -> _Snapshot:
    return _Snapshot(
        flags=envelope.payload.flags,
        issued_at=parse_wire_time(envelope.payload.issued_at),
        from_cache=from_cache,
    )


class Client:
    """Polls the ruleset export and answers evaluations from its snapshot.

    Create with ``fortressflag.create``; direct construction is internal.
    """

    def __init__(
        self,
        configuration: ResolvedConfiguration,
        fetcher: Transport,
        *,
        now_s: Any = None,
        random_in_range: RandomInRange | None = None,
    ) -> None:
        self._configuration = configuration
        self._fetcher = fetcher
        self._cache = FileCache(configuration.cache_path) if configuration.cache_path else None

        self._snapshot: _Snapshot | None = None

        self._state_lock = threading.Lock()
        self._last_fetch_at: float | None = None
        self._last_fetch_status = "neverFetched"
        self._last_rejection: RejectionCode | None = None
        self._etag = ""
        self._consecutive_failures = 0
        self._cache_state = "disabled" if self._cache is None else "empty"

        self._counters_lock = threading.Lock()
        self._served = 0
        self._fallback_no_snapshot = 0
        self._fallback_unknown_flag = 0
        self._fallback_kind_mismatch = 0
        self._fallback_no_value = 0

        self._first_attempt = threading.Event()
        self._network_ready = threading.Event()
        self._stop = threading.Event()
        self._start_lock = threading.Lock()
        self._started = False
        self._thread: threading.Thread | None = None

        self._now_s = now_s if now_s is not None else time.time
        self._random_in_range: RandomInRange = (
            random_in_range if random_in_range is not None else _random.uniform
        )

    def start(self, timeout: float | None = None) -> StartOutcome:
        """Load the cache if configured, launch the poller, and block until the first
        fetch attempt completes or the timeout elapses.

        Never raises: the worst outcome is "serving fallbacks until the network appears",
        stated in the StartOutcome. Calling start again reports the current state without
        side effects.
        """
        with self._start_lock:
            if not self._started:
                self._started = True
                self._load_cache()
                self._thread = threading.Thread(
                    target=self._poll_loop, name="fortressflag-poller", daemon=True
                )
                self._thread.start()

        self._first_attempt.wait(timeout)
        if self._network_ready.is_set():
            return StartOutcome.READY
        snapshot = self._snapshot
        if snapshot is not None and snapshot.from_cache:
            return StartOutcome.CACHE_ONLY
        return StartOutcome.READY if self._network_ready.is_set() else StartOutcome.TIMED_OUT

    def close(self) -> None:
        """Stop the poller and wait briefly for it. Idempotent, and safe before start."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=self._configuration.http_timeout_s + 1.0)

    def bool_value(self, flag_key: str, context: Context, fallback: bool) -> bool:
        value, ok = self._value(flag_key, context, "boolean")
        return value if ok and isinstance(value, bool) else fallback

    def string_value(self, flag_key: str, context: Context, fallback: str) -> str:
        value, ok = self._value(flag_key, context, "string")
        return value if ok and isinstance(value, str) else fallback

    def number_value(self, flag_key: str, context: Context, fallback: float) -> float:
        value, ok = self._value(flag_key, context, "number")
        return value if ok and isinstance(value, float) else fallback

    def diagnostics(self) -> Diagnostics:
        snapshot = self._snapshot
        with self._counters_lock:
            resolutions = ResolutionCounters(
                served=self._served,
                fallback_no_snapshot=self._fallback_no_snapshot,
                fallback_unknown_flag=self._fallback_unknown_flag,
                fallback_kind_mismatch=self._fallback_kind_mismatch,
                fallback_no_value=self._fallback_no_value,
            )
        with self._state_lock:
            return Diagnostics(
                last_fetch_at=self._last_fetch_at,
                last_fetch_status=self._last_fetch_status,
                last_rejection=str(self._last_rejection) if self._last_rejection else "",
                etag=self._etag,
                consecutive_failures=self._consecutive_failures,
                snapshot_issued_at=snapshot.issued_at if snapshot else None,
                snapshot_source=("cache" if snapshot.from_cache else "network") if snapshot else "",
                flag_count=len(snapshot.flags) if snapshot else 0,
                cache_state=self._cache_state,
                resolutions=resolutions,
            )

    # -- internals ---------------------------------------------------------------------

    def _load_cache(self) -> None:
        if self._cache is None:
            return
        raw = self._cache.load()
        if raw is None:
            return
        # Expiry deliberately unenforced: THE cache-load half of the contract's expiry
        # asymmetry — a service that restarts after a long outage keeps evaluating with
        # what it last saw. See Expectations.enforce_expiry.
        envelope, _code = verify_envelope(
            raw,
            self._configuration.signature,
            Expectations(
                environment=self._configuration.environment,
                now_s=self._now_s(),
                enforce_expiry=False,
            ),
        )
        with self._state_lock:
            if envelope is None:
                self._cache_state = "loadFailed"
                return
            self._cache_state = "loaded"
        self._snapshot = _snapshot_of(envelope, from_cache=True)

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            with self._state_lock:
                etag = self._etag
            outcome = self._fetcher.fetch_ruleset(etag)
            if self._stop.is_set():
                self._first_attempt.set()
                return
            self._record(outcome)
            self._first_attempt.set()

            with self._state_lock:
                failures = self._consecutive_failures
            if failures == 0:
                delay_s = poll_delay_s(self._configuration.poll_interval_s, self._random_in_range)
            elif outcome.kind is FetchKind.RATE_LIMITED and outcome.retry_after_seconds > 0:
                delay_s = retry_delay_with_server_hint_s(
                    outcome.retry_after_seconds, failures, self._random_in_range
                )
            else:
                delay_s = retry_delay_s(failures, self._random_in_range)
            # Event.wait, never time.sleep: close() must interrupt a 30-minute backoff
            # immediately, and a daemon thread parked in sleep would also survive to
            # confuse interpreter shutdown.
            if self._stop.wait(delay_s):
                return

    def _record(self, outcome: FetchOutcome) -> None:
        """Turn one fetch outcome into snapshot/cache/diagnostics updates — the ONLY
        mutation site."""
        now = self._now_s()
        if outcome.kind is FetchKind.SUCCESS:
            envelope, rejection = verify_envelope(
                outcome.raw,
                self._configuration.signature,
                Expectations(
                    environment=self._configuration.environment,
                    now_s=now,
                    # A live response past expiry is the replay window — refused.
                    enforce_expiry=True,
                ),
            )
            if envelope is None:
                # A rejected envelope never dislodges the snapshot or the cache: the last
                # verified state keeps serving, and the rejection is one diagnostics()
                # read away.
                with self._state_lock:
                    self._last_fetch_at = now
                    self._last_fetch_status = "rejectedEnvelope"
                    self._last_rejection = rejection
                    self._consecutive_failures += 1
                return
            stored: bool | None = None
            if self._cache is not None:
                stored = self._cache.store(envelope.raw)
            self._snapshot = _snapshot_of(envelope, from_cache=False)
            with self._state_lock:
                self._last_fetch_at = now
                self._last_fetch_status = "fresh"
                self._last_rejection = None
                self._etag = outcome.etag
                self._consecutive_failures = 0
                if stored is not None:
                    self._cache_state = "stored" if stored else "storeFailed"
            self._network_ready.set()
            return

        status_by_kind = {
            FetchKind.NOT_MODIFIED: "notModified",
            FetchKind.UNAUTHORIZED: "unauthorized",
            FetchKind.RATE_LIMITED: "rateLimited",
            FetchKind.SERVER_ERROR: "serverError",
            FetchKind.RESPONSE_TOO_LARGE: "responseTooLarge",
            FetchKind.UNEXPECTED_STATUS: "unexpectedStatus",
            FetchKind.TRANSPORT_ERROR: "transportError",
        }
        with self._state_lock:
            self._last_fetch_at = now
            self._last_fetch_status = status_by_kind[outcome.kind]
            if outcome.kind is FetchKind.NOT_MODIFIED:
                # The steady state of a polling fleet: the cached ruleset is current.
                self._consecutive_failures = 0
            else:
                # Including 401/403 — a revoked key. The contract's instruction: answered
                # like any failed fetch — keep evaluating with the last downloaded
                # ruleset, indefinitely, until given a new key.
                self._consecutive_failures += 1

    def _value(self, flag_key: str, context: Context, want_kind: str) -> tuple[Any, bool]:
        """The getters' shared path: one snapshot read, kind check, evaluate."""
        snapshot = self._snapshot
        if snapshot is None:
            with self._counters_lock:
                self._fallback_no_snapshot += 1
            return None, False
        config = snapshot.flags.get(flag_key)
        if config is None:
            # Absence means the flag does not exist or was archived: the caller's
            # fallback is the contract's answer.
            with self._counters_lock:
                self._fallback_unknown_flag += 1
            return None, False
        if config.kind != want_kind:
            # Asking bool of a string flag is a caller bug, but never a raise: fallback,
            # and the mismatch is visible on diagnostics.
            with self._counters_lock:
                self._fallback_kind_mismatch += 1
            return None, False
        value, ok = evaluate_flag(config, context.tags, context.key, flag_key)
        if not ok:
            with self._counters_lock:
                self._fallback_no_value += 1
            return None, False
        with self._counters_lock:
            self._served += 1
        return value, True
