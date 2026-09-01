"""The public surface of the FortressFlag Python server SDK.

Everything the SDK exports is enumerated in ``__all__`` (the sibling SDKs' one-file-surface
rule); everything else is underscore-internal. The surface arrives with the later PRs; the
scaffold ships the package so the build has an import target from day one.
"""

__all__: list[str] = []
