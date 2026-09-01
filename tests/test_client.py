from __future__ import annotations

import os
import stat
from pathlib import Path

from tests.support import FIXTURE_NOW_S, fixture_envelope, fixture_payload

from fortressflag._client import Client, Context, StartOutcome
from fortressflag._configuration import Configuration, resolve_configuration
from fortressflag._transport import FetchKind, FetchOutcome

CTX = Context(key="user-1", tags={"cohort": "beta"})


class ScriptedFetcher:
    """Plays outcomes in order, then repeats the last forever."""

    def __init__(self, outcomes: list[FetchOutcome]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def fetch_ruleset(self, _etag: str) -> FetchOutcome:
        outcome = self.outcomes[min(self.calls, len(self.outcomes) - 1)]
        self.calls += 1
        return outcome


def good_fetch() -> FetchOutcome:
    return FetchOutcome(
        kind=FetchKind.SUCCESS, raw=fixture_envelope(fixture_payload()), etag='"e1"'
    )


def make_client(fetcher: object, **config: object) -> Client:
    resolved = resolve_configuration(Configuration(key="ffs_dev_k", **config))  # type: ignore[arg-type]
    return Client(
        resolved, fetcher, now_s=lambda: FIXTURE_NOW_S, random_in_range=lambda a, b: (a + b) / 2
    )  # type: ignore[arg-type]


def poll_once(client: Client) -> None:
    """Drive one record() cycle synchronously — the poller thread is not used in these
    tests (the chaos suite exercises the real thread)."""
    outcome = client._fetcher.fetch_ruleset(client._etag)  # noqa: SLF001 - test drives internals
    client._record(outcome)


def test_start_ready_and_start_again_is_a_pure_status_read() -> None:
    fetcher = ScriptedFetcher([good_fetch()])
    client = make_client(fetcher)
    assert client.start(timeout=5.0) is StartOutcome.READY
    calls_after_first = fetcher.calls
    assert client.start(timeout=0.1) is StartOutcome.READY
    assert fetcher.calls >= calls_after_first  # no restart; the poller owns the schedule
    client.close()


def test_timed_out_serving_defaults_and_fallbacks_serve() -> None:
    client = make_client(ScriptedFetcher([FetchOutcome(kind=FetchKind.TRANSPORT_ERROR)]))
    assert client.start(timeout=5.0) is StartOutcome.TIMED_OUT
    assert client.bool_value("dark-mode", CTX, True) is True
    client.close()


def test_cache_only_when_the_file_answers_and_the_network_does_not(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    stale = fixture_envelope(
        fixture_payload(issuedAt="2026-08-21T07:00:00Z", expiresAt="2026-08-21T07:30:00Z")
    )
    path.write_bytes(stale)
    client = make_client(
        ScriptedFetcher([FetchOutcome(kind=FetchKind.TRANSPORT_ERROR)]), cache_path=str(path)
    )
    assert client.start(timeout=5.0) is StartOutcome.CACHE_ONLY
    assert client.bool_value("dark-mode", CTX, False) is True
    assert client.diagnostics().snapshot_source == "cache"
    client.close()


def test_a_rejected_envelope_never_dislodges_anything() -> None:
    hostile = FetchOutcome(
        kind=FetchKind.SUCCESS,
        raw=fixture_envelope(fixture_payload(environment="prod")),
        etag='"e2"',
    )
    client = make_client(ScriptedFetcher([good_fetch(), hostile]))
    assert client.start(timeout=5.0) is StartOutcome.READY
    poll_once(client)
    assert client.bool_value("dark-mode", CTX, False) is True  # held value survives
    diagnostics = client.diagnostics()
    assert diagnostics.last_fetch_status == "rejectedEnvelope"
    assert diagnostics.last_rejection == "environmentMismatch"
    assert diagnostics.etag == '"e1"'  # the rejected response's etag was NOT adopted
    client.close()


def test_a_revoked_key_keeps_serving() -> None:
    client = make_client(ScriptedFetcher([good_fetch(), FetchOutcome(kind=FetchKind.UNAUTHORIZED)]))
    client.start(timeout=5.0)
    poll_once(client)
    poll_once(client)
    assert client.bool_value("dark-mode", CTX, False) is True
    diagnostics = client.diagnostics()
    assert diagnostics.last_fetch_status == "unauthorized"
    assert diagnostics.consecutive_failures == 2
    client.close()


def test_wholesale_overwrite_drops_departed_flags() -> None:
    second = FetchOutcome(
        kind=FetchKind.SUCCESS,
        raw=fixture_envelope(
            fixture_payload(
                flags={"checkout-cta": {"kind": "string", "default": "buy-now", "rules": []}}
            )
        ),
        etag='"e2"',
    )
    client = make_client(ScriptedFetcher([good_fetch(), second]))
    client.start(timeout=5.0)
    assert client.bool_value("dark-mode", CTX, False) is True
    poll_once(client)
    assert client.bool_value("dark-mode", CTX, False) is False  # archived → fallback
    assert client.diagnostics().resolutions.fallback_unknown_flag == 1
    client.close()


def test_kind_mismatch_answers_the_fallback_never_a_raise() -> None:
    client = make_client(ScriptedFetcher([good_fetch()]))
    client.start(timeout=5.0)
    assert client.bool_value("checkout-cta", CTX, True) is True
    assert client.string_value("dark-mode", CTX, "x") == "x"
    assert client.number_value("dark-mode", CTX, 7.0) == 7.0
    assert client.diagnostics().resolutions.fallback_kind_mismatch == 3
    client.close()


def test_diagnostics_carries_no_key_in_any_form() -> None:
    client = make_client(ScriptedFetcher([good_fetch()]))
    client.start(timeout=5.0)
    assert "ffs_" not in repr(client.diagnostics())
    client.close()


def test_cache_write_is_verbatim_mode_600_and_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    first = good_fetch()
    client = make_client(ScriptedFetcher([first]), cache_path=str(path))
    client.start(timeout=5.0)
    assert client.diagnostics().cache_state == "stored"
    assert path.read_bytes() == first.raw
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    client.close()

    reborn = make_client(
        ScriptedFetcher([FetchOutcome(kind=FetchKind.TRANSPORT_ERROR)]), cache_path=str(path)
    )
    assert reborn.start(timeout=5.0) is StartOutcome.CACHE_ONLY
    assert reborn.bool_value("dark-mode", CTX, False) is True
    reborn.close()


def test_a_corrupt_cache_degrades_to_load_failed(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_bytes(b"not-an-envelope")
    client = make_client(
        ScriptedFetcher([FetchOutcome(kind=FetchKind.TRANSPORT_ERROR)]), cache_path=str(path)
    )
    assert client.start(timeout=5.0) is StartOutcome.TIMED_OUT
    assert client.diagnostics().cache_state == "loadFailed"
    client.close()
