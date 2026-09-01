"""Transport tests against a REAL local HTTP server — the header-allowlist assertion is the
mechanical enforcement of "the contract names every header"."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from fortressflag._configuration import Configuration, resolve_configuration
from fortressflag._transport import (
    MAX_RESPONSE_BYTES,
    FetchKind,
    Transport,
    parse_retry_after_seconds,
)

Handler = Callable[[BaseHTTPRequestHandler], None]


class _Server:
    def __init__(self) -> None:
        self.handler: Handler = lambda request: None
        self.seen_headers: list[str] = []
        outer = self

        class RequestHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - http.server's naming
                outer.seen_headers = list(self.headers.keys())
                outer.handler(self)

            def log_message(self, *_args: object) -> None:
                pass

        self.http = HTTPServer(("127.0.0.1", 0), RequestHandler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.http.server_port}"

    def close(self) -> None:
        self.http.shutdown()
        self.http.server_close()


@pytest.fixture
def server() -> Iterator[_Server]:
    instance = _Server()
    yield instance
    instance.close()


def transport_for(base_url: str, timeout_s: float = 2.0) -> Transport:
    return Transport(
        resolve_configuration(
            Configuration(key="ffs_dev_k12345", base_url=base_url, http_timeout_s=timeout_s)
        )
    )


def test_sends_exactly_the_contracts_headers(server: _Server) -> None:
    def handler(request: BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.send_header("ETag", '"e1"')
        request.end_headers()
        request.wfile.write(b"{}")

    server.handler = handler
    outcome = transport_for(server.base_url).fetch_ruleset('"old"')
    assert outcome.kind is FetchKind.SUCCESS
    # Transport-mechanical headers (Host/Connection/User-Agent) are the platform's;
    # everything else must be the contract's three and nothing more.
    allowed = {
        "authorization",
        "accept",
        "if-none-match",
        "host",
        "connection",
        "user-agent",
        "accept-encoding",
    }
    for header in server.seen_headers:
        assert header.lower() in allowed, f"unexpected header: {header}"
    lowered = [h.lower() for h in server.seen_headers]
    assert "authorization" in lowered
    assert "if-none-match" in lowered


def test_url_carries_sv1_and_the_etag_round_trips(server: _Server) -> None:
    seen: dict[str, str] = {}

    def handler(request: BaseHTTPRequestHandler) -> None:
        seen["path"] = request.path
        seen["inm"] = request.headers.get("If-None-Match", "")
        request.send_response(200)
        request.send_header("ETag", '"e2"')
        request.end_headers()
        request.wfile.write(b"{}")

    server.handler = handler
    outcome = transport_for(server.base_url).fetch_ruleset('"e1"')
    assert seen["path"] == "/v1/server/ruleset?sv=1"
    assert seen["inm"] == '"e1"'
    assert outcome.etag == '"e2"'


@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (304, {}, FetchKind.NOT_MODIFIED),
        (401, {}, FetchKind.UNAUTHORIZED),
        (403, {}, FetchKind.UNAUTHORIZED),
        (429, {"Retry-After": "17"}, FetchKind.RATE_LIMITED),
        (503, {}, FetchKind.SERVER_ERROR),
        (302, {"Location": "http://evil.example/"}, FetchKind.UNEXPECTED_STATUS),
        (418, {}, FetchKind.UNEXPECTED_STATUS),
    ],
)
def test_status_mapping(
    server: _Server, status: int, headers: dict[str, str], expected: FetchKind
) -> None:
    def handler(request: BaseHTTPRequestHandler) -> None:
        request.send_response(status)
        for name, value in headers.items():
            request.send_header(name, value)
        request.send_header("Content-Length", "0")
        request.end_headers()

    server.handler = handler
    outcome = transport_for(server.base_url).fetch_ruleset("")
    assert outcome.kind is expected
    if outcome.kind is FetchKind.RATE_LIMITED:
        assert outcome.retry_after_seconds == 17


def test_a_body_over_1mib_is_refused_and_at_1mib_accepted(server: _Server) -> None:
    size = {"n": MAX_RESPONSE_BYTES + 1}

    def handler(request: BaseHTTPRequestHandler) -> None:
        request.send_response(200)
        request.send_header("Content-Length", str(size["n"]))
        request.end_headers()
        request.wfile.write(b" " * size["n"])

    server.handler = handler
    transport = transport_for(server.base_url)
    assert transport.fetch_ruleset("").kind is FetchKind.RESPONSE_TOO_LARGE
    size["n"] = MAX_RESPONSE_BYTES
    assert transport.fetch_ruleset("").kind is FetchKind.SUCCESS


def test_a_hung_server_maps_to_transport_error(server: _Server) -> None:
    def handler(request: BaseHTTPRequestHandler) -> None:
        threading.Event().wait(5.0)

    server.handler = handler
    outcome = transport_for(server.base_url, timeout_s=0.2).fetch_ruleset("")
    assert outcome.kind is FetchKind.TRANSPORT_ERROR


def test_a_refused_connection_maps_to_transport_error() -> None:
    outcome = transport_for("http://127.0.0.1:1").fetch_ruleset("")
    assert outcome.kind is FetchKind.TRANSPORT_ERROR


def test_parse_retry_after_delta_seconds_only() -> None:
    assert parse_retry_after_seconds("17") == 17
    assert parse_retry_after_seconds("") == 0
    assert parse_retry_after_seconds("-1") == 0
    assert parse_retry_after_seconds("Wed, 21 Oct 2026 07:28:00 GMT") == 0
