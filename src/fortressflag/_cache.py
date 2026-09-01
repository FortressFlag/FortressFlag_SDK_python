"""The opt-in durable cache (ADR-0016).

The file named by ``cache_path`` holds the last VERIFIED envelope's raw bytes — verbatim,
never a re-serialisation (re-serialising would strip future fields and break the signature
on reload), never parsed values, never the key, never any evaluation context. The caller
re-verifies on load (expiry unenforced — the asymmetry), so poisoning the cache requires
forging whatever the transport requires, and the cache inherits every transport guarantee
for free.

Every failure here degrades to in-memory operation with a note on diagnostics() — a cache
problem is never the customer's problem.
"""

from __future__ import annotations

import contextlib
import os
import tempfile

from ._transport import MAX_RESPONSE_BYTES


class FileCache:
    def __init__(self, path: str) -> None:
        self._path = path

    def load(self) -> bytes | None:
        """The cached envelope bytes, or None when there is nothing usable.

        A file larger than the transport's own response cap was not written by us; it is
        refused rather than read whole (a hostile or broken writer must not balloon this
        process's memory) — the read stops one byte past the cap.
        """
        try:
            with open(self._path, "rb") as file:
                raw = file.read(MAX_RESPONSE_BYTES + 1)
        except OSError:
            return None
        if len(raw) == 0 or len(raw) > MAX_RESPONSE_BYTES:
            return None
        return raw

    def store(self, raw: bytes) -> bool:
        """Atomically replace the cache file with raw.

        Temp-file-in-the-SAME-directory + ``os.replace``, deliberately: a temp file in the
        system temp directory makes the replace a cross-filesystem move, which fails
        (EXDEV) — the "cache that never persists and nothing notices" bug class (on
        Android the equivalent failed silently under SELinux and every write was lost).
        The replace is what makes a crash mid-write leave the last good envelope in place
        rather than a truncated one. ``tempfile.mkstemp`` creates 0600 — asserted by a
        test so a refactor to a laxer primitive cannot pass silently.
        """
        if len(raw) == 0 or len(raw) > MAX_RESPONSE_BYTES:
            return False
        directory = os.path.dirname(self._path) or "."
        try:
            fd, temp_path = tempfile.mkstemp(prefix=".fortressflag-cache-", dir=directory)
        except OSError:
            return False
        try:
            os.write(fd, raw)
            os.close(fd)
            os.replace(temp_path, self._path)
            return True
        except OSError:
            with contextlib.suppress(OSError):
                os.close(fd)
            with contextlib.suppress(OSError):
                os.remove(temp_path)
            return False
