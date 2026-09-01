"""The transport: one GET, treated as talking to a potentially hostile network.

The three rules every FortressFlag SDK transport carries (ports of the sibling SDKs'
rules):

- An explicit per-request timeout — a hung server must not park the poller thread.
- Redirects are refused: the opener is built WITHOUT a redirect handler, so a 3xx surfaces
  as-is and maps to the unexpected-status outcome — following one could replay the
  Authorization header, which carries a genuine secret, to wherever it points.
- The response body is capped at 1 MiB, read one byte past the cap — a hostile or broken
  server must not balloon this process's memory. Real payloads are kilobytes.

urllib's sharp edge, handled here so nothing above sees it: ``HTTPError`` IS the response
for 4xx/5xx (un-caught, a revoked key's 401 becomes an exception on the poller thread;
caught wrongly, the status and Retry-After are lost), and ``URLError`` wraps refused
connections and timeouts — both are enumerated outcomes, never raises.
"""

from __future__ import annotations

import enum
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.client import HTTPResponse
from typing import Final

from ._configuration import ResolvedConfiguration
from ._envelope import SUPPORTED_SERVER_CONTRACT_VERSION

# What this transport reads responses from: a real HTTPResponse, or the HTTPError that IS
# the response for non-2xx statuses (typeshed types its status as int | None, hence the
# coercions below).
_WireResponse = HTTPResponse | urllib.error.HTTPError


#: Bounds a response body. Shared with the cache's load bound.
MAX_RESPONSE_BYTES: Final[int] = 1 << 20


class FetchKind(enum.StrEnum):
    SUCCESS = "success"
    NOT_MODIFIED = "notModified"  # 304 — a success: the cached ruleset is current
    UNAUTHORIZED = "unauthorized"  # 401/403 — revoked or wrong key; keep serving
    RATE_LIMITED = "rateLimited"  # 429
    SERVER_ERROR = "serverError"  # 5xx
    UNEXPECTED_STATUS = "unexpectedStatus"  # incl. a refused redirect's 3xx
    TRANSPORT_ERROR = "transportError"  # dial/timeout — the network itself failed
    RESPONSE_TOO_LARGE = "responseTooLarge"


@dataclass(frozen=True, slots=True)
class FetchOutcome:
    kind: FetchKind
    raw: bytes = b""
    etag: str = ""
    status: int = 0
    retry_after_seconds: int = 0


class Transport:
    """One conditional GET of the ruleset export — exactly the request the contract shows,
    no more: Authorization, Accept, If-None-Match. There is no SDK-version header and no
    telemetry; an undocumented header would be an additive contract change that goes
    through an ADR (ADR-0016)."""

    def __init__(self, configuration: ResolvedConfiguration) -> None:
        self._url = (
            f"{configuration.base_url}/v1/server/ruleset?sv={SUPPORTED_SERVER_CONTRACT_VERSION}"
        )
        self._key = configuration.key
        self._timeout_s = configuration.http_timeout_s
        # No HTTPRedirectHandler: a 3xx is returned as the response (or raised as
        # HTTPError, which the except arm maps like any other status).
        self._opener = urllib.request.OpenerDirector()
        self._opener.add_handler(urllib.request.HTTPHandler())
        self._opener.add_handler(urllib.request.HTTPSHandler())
        self._opener.add_handler(urllib.request.HTTPErrorProcessor())
        # Raises HTTPError for every non-2xx the processor routes — including the 3xx a
        # redirect handler would have followed; without it urllib's error dispatch
        # KeyErrors instead of erroring.
        self._opener.add_handler(urllib.request.HTTPDefaultErrorHandler())

    def fetch_ruleset(self, etag: str) -> FetchOutcome:
        request = urllib.request.Request(self._url, method="GET")
        request.add_header("Authorization", f"Bearer {self._key}")
        request.add_header("Accept", "application/json")
        if etag != "":
            request.add_header("If-None-Match", etag)
        try:
            with self._opener.open(request, timeout=self._timeout_s) as response:
                return self._read_success(response)
        except urllib.error.HTTPError as response:
            # The error IS the response (urllib raises for anything >= 400 — and, with the
            # error processor, for un-handled 3xx too).
            with response:
                return self._map_status(response)
        except (urllib.error.URLError, OSError, ValueError):
            # Refused connections, DNS failures, timeouts, malformed URLs from a hostile
            # base_url — the snapshot keeps serving either way.
            return FetchOutcome(kind=FetchKind.TRANSPORT_ERROR)

    def _read_success(self, response: _WireResponse) -> FetchOutcome:
        status = response.status or 0
        if status == 304:
            return FetchOutcome(kind=FetchKind.NOT_MODIFIED)
        if status != 200:
            return self._map_status(response)
        # One byte past the cap distinguishes "exactly at the cap" from "over it".
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            return FetchOutcome(kind=FetchKind.RESPONSE_TOO_LARGE)
        return FetchOutcome(kind=FetchKind.SUCCESS, raw=body, etag=_header(response, "ETag"))

    def _map_status(self, response: _WireResponse) -> FetchOutcome:
        status = response.status or 0
        if status == 304:
            return FetchOutcome(kind=FetchKind.NOT_MODIFIED)
        if status in (401, 403):
            return FetchOutcome(kind=FetchKind.UNAUTHORIZED)
        if status == 429:
            return FetchOutcome(
                kind=FetchKind.RATE_LIMITED,
                retry_after_seconds=parse_retry_after_seconds(_header(response, "Retry-After")),
            )
        if status >= 500:
            return FetchOutcome(kind=FetchKind.SERVER_ERROR, status=status)
        return FetchOutcome(kind=FetchKind.UNEXPECTED_STATUS, status=status)


def parse_retry_after_seconds(header: str) -> int:
    """Read Retry-After as delta-seconds ONLY.

    The HTTP-date form is deliberately not parsed (the sibling SDKs' rule): date parsing
    against a wrong local clock can produce an enormous delay, and the backoff caps
    whatever this returns anyway.
    """
    if header == "" or not header.isascii() or not header.isdigit():
        return 0
    try:
        return int(header)
    except ValueError:
        return 0


def _header(response: _WireResponse, name: str) -> str:
    headers = response.headers
    get = getattr(headers, "get", None)
    if get is None:
        return ""
    value = get(name, "")
    return value if isinstance(value, str) else ""
