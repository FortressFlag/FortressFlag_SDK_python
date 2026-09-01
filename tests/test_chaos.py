"""The suite that proves the one thing this SDK actually promises: flagging can fail in any
way at all, and the customer's process neither crashes nor sees an error.

Every other test checks that a specific thing works; these check that nothing breaks when
everything is wrong at once. Ported from the Go SDK's chaos suite — including the
concurrent variant done with REAL threads: Python has them, and a torn read the GIL
happens to forgive today is still a bug under free-threading tomorrow.
"""

from __future__ import annotations

import threading
from pathlib import Path

from tests.support import FIXTURE_NOW_S, fixture_envelope, fixture_payload

from fortressflag._client import Client, Context
from fortressflag._configuration import (
    Configuration,
    resolve_configuration,
    signature_required,
)
from fortressflag._transport import FetchKind, FetchOutcome

CTX = Context(key="user-1", tags={"cohort": "beta"})


def hostile_outcomes() -> list[tuple[str, FetchOutcome]]:
    """Every way the world can be wrong, in four groups (the Go suite's table)."""

    def success(raw: bytes) -> FetchOutcome:
        return FetchOutcome(kind=FetchKind.SUCCESS, raw=raw, etag='"hostile"')

    bodies: list[tuple[str, bytes]] = [
        ("empty body", b""),
        ("captive portal", b"<html>please log in</html>"),
        ("truncated JSON", b"{"),
        ("JSON null", b"null"),
        ("zero bytes", b"\x00" * 4096),
        ("wrong environment", fixture_envelope(fixture_payload(environment="prod"))),
        ("unsupported sv", fixture_envelope(fixture_payload(sv=99))),
        (
            "expired live payload — the replay window",
            fixture_envelope(
                fixture_payload(issuedAt="2026-08-21T08:00:00Z", expiresAt="2026-08-21T08:30:00Z")
            ),
        ),
        (
            "issuedAt in the future",
            fixture_envelope(fixture_payload(issuedAt="2026-08-21T12:00:00Z")),
        ),
        ("truncated envelope", fixture_envelope(fixture_payload())[:20]),
        (
            "rules is not a list",
            fixture_envelope(
                fixture_payload(flags={"x": {"kind": "boolean", "rules": "not-a-list"}})
            ),
        ),
        ("flags is not a map", fixture_envelope(fixture_payload(flags="not-a-map"))),
        (
            "unknown flag kind — whole-payload rejection",
            fixture_envelope(fixture_payload(flags={"x": {"kind": "datetime", "rules": []}})),
        ),
    ]
    outcomes = [(name, success(raw)) for name, raw in bodies]
    outcomes += [
        ("transport error", FetchOutcome(kind=FetchKind.TRANSPORT_ERROR)),
        ("unauthorized", FetchOutcome(kind=FetchKind.UNAUTHORIZED)),
        ("rate limited", FetchOutcome(kind=FetchKind.RATE_LIMITED)),
        (
            "rate limited for a year",
            FetchOutcome(kind=FetchKind.RATE_LIMITED, retry_after_seconds=31_536_000),
        ),
        ("server error 500", FetchOutcome(kind=FetchKind.SERVER_ERROR, status=500)),
        ("server error 503", FetchOutcome(kind=FetchKind.SERVER_ERROR, status=503)),
        ("teapot", FetchOutcome(kind=FetchKind.UNEXPECTED_STATUS, status=418)),
        ("bad request", FetchOutcome(kind=FetchKind.UNEXPECTED_STATUS, status=400)),
        ("response too large", FetchOutcome(kind=FetchKind.RESPONSE_TOO_LARGE)),
        ("304 with nothing cached behind it", FetchOutcome(kind=FetchKind.NOT_MODIFIED)),
    ]
    return outcomes


class PushFetcher:
    """A fetcher whose next outcome the test chooses per call."""

    def __init__(self) -> None:
        self.next = FetchOutcome(kind=FetchKind.TRANSPORT_ERROR)

    def fetch_ruleset(self, _etag: str) -> FetchOutcome:
        return self.next


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
    client._record(client._fetcher.fetch_ruleset(client._etag))  # noqa: SLF001


def test_a_client_holding_a_good_value_never_loses_it(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    fetcher = PushFetcher()
    fetcher.next = good_fetch()
    client = make_client(fetcher, cache_path=str(path))
    assert client.start(timeout=5.0).value == "ready"
    cached_before = path.read_bytes()

    for name, outcome in hostile_outcomes():
        fetcher.next = outcome
        poll_once(client)
        assert client.bool_value("dark-mode", CTX, False) is True, name
        assert client.string_value("checkout-cta", CTX, "fallback") == "buy-now", name
    assert path.read_bytes() == cached_before, "hostile outcomes reached the cache file"
    client.close()


def test_a_cold_client_answers_fallbacks_forever(tmp_path: Path) -> None:
    fetcher = PushFetcher()
    client = make_client(fetcher)
    for name, outcome in hostile_outcomes():
        fetcher.next = outcome
        poll_once(client)
        assert client.bool_value("dark-mode", CTX, False) is False, name
        assert client.number_value("retry-limit", CTX, 7.0) == 7.0, name
    client.close()


def test_under_a_required_policy_every_signature_shape_rejects() -> None:
    fetcher = PushFetcher()
    resolved = resolve_configuration(
        Configuration(key="ffs_dev_k", signature=signature_required({"k1": bytes(32)}))
    )
    client = Client(
        resolved,
        fetcher,  # type: ignore[arg-type]
        now_s=lambda: FIXTURE_NOW_S,
        random_in_range=lambda a, b: (a + b) / 2,
    )
    for sig in [
        "",
        "garbage",
        "ed25519:AAAA",
        "p256:k1:AAAA",
        "ed25519:unknown:AAAA",
        "ed25519:k1:AAAA",
    ]:
        fetcher.next = FetchOutcome(
            kind=FetchKind.SUCCESS, raw=fixture_envelope(fixture_payload(), sig=sig), etag='"s"'
        )
        poll_once(client)
        diagnostics = client.diagnostics()
        assert diagnostics.last_fetch_status == "rejectedEnvelope", sig
        assert diagnostics.flag_count == 0, sig
    client.close()


def test_concurrent_getters_during_hostile_swaps() -> None:
    """Trap 10's real-thread port: 8 reader threads hammer the getters while the main
    thread swaps hostile and good outcomes. Any lost held value or raise fails the test."""
    fetcher = PushFetcher()
    fetcher.next = good_fetch()
    client = make_client(fetcher)
    client.start(timeout=5.0)

    stop = threading.Event()
    failures: list[str] = []

    def hammer() -> None:
        while not stop.is_set():
            try:
                if client.bool_value("dark-mode", CTX, False) is not True:
                    failures.append("held value lost")
                    return
                client.diagnostics()
            except Exception as error:  # noqa: BLE001 - the assertion IS "never raises"
                failures.append(f"raised: {error!r}")
                return

    threads = [threading.Thread(target=hammer, daemon=True) for _ in range(8)]
    for thread in threads:
        thread.start()
    try:
        for _cycle in range(50):
            for _name, outcome in hostile_outcomes():
                fetcher.next = outcome
                poll_once(client)
            fetcher.next = good_fetch()
            poll_once(client)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=5.0)
        client.close()
    assert failures == []


def test_a_poisoned_cache_cannot_smuggle_a_snapshot(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_bytes(fixture_envelope(fixture_payload(environment="prod")))
    client = make_client(PushFetcher(), cache_path=str(path))
    assert client.start(timeout=5.0).value == "timed-out-serving-defaults"
    assert client.diagnostics().cache_state == "loadFailed"
    client.close()
