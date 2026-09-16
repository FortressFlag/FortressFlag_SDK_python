# FortressFlag_SDK_python — Agent & Contributor Guide

> **This repo inherits the FortressFlag founding principles.** The canonical document lives in
> the backend repo — read it before design decisions:
>
> - GitHub: <https://github.com/FortressFlag/FortressFlag_Backend/blob/development/CLAUDE.md>
> - Local clone: `~/Workspace/FortressFlag_Backend/CLAUDE.md`
>
> Priority order when in doubt: **Security → Compliance → Efficiency → Cost.**

---

## 1. This Repo

The **Python server SDK** (backend ADR-0020, inheriting ADR-0016's decisions): pure stdlib,
sync API. It embeds in a customer's backend, downloads the full evaluable ruleset for one
project + environment via an `ffs_` server key (`GET /v1/server/ruleset`), and evaluates
flags **locally, in-process**. It implements
`FortressFlag_Standards/contracts/server-contract-v1.md` and ports
`vectors/evaluation.json` + `vectors/buckets.json` as unit tests. The contract is owned by
`FortressFlag_Backend`; changes arrive only via ADRs there.

## 2. Fail-safe evaluation (Founding §8.1, §8.4)

- **After construction, the SDK never raises to the caller and never exits the process.**
  The host is the customer's PROCESS. CI greps library sources for `sys.exit(`, `os._exit(`
  and `os.abort(`; the never-raise promise on getters is enforced by the chaos suite
  (a `raise` grep would fire on the one legal site — the constructor — and the fix would be
  weakening the grep).
- `create()` is the ONE place the SDK may raise (`MalformedKeyError`, before anything
  serves). Getters always answer; every failure resolves to the caller's fallback with the
  reason on `diagnostics()`. There is no compiled-in `False` tier (ADR-0016).
- **Signatures verify for real, fail-closed by default** (ADR-0025): `Configuration.signature`
  defaults to required-with-`FORTRESSFLAG_PRODUCTION`; `SIGNATURE_DISABLED` is the explicit
  local-dev opt-out. The Ed25519 verifier is vendored in `_ed25519.py` (verify-only, RFC
  8032 arithmetic on `int`, pinned to the RFC §7.1 vectors) — one code path, no platform
  provider, no dependency. Never add a fallback to a crypto library.
- The last verified ruleset serves through any outage indefinitely. **Expiry governs
  freshness, never validity**: a live response past `expiresAt` is refused; a cache-file
  load never is.
- **The poller must never block interpreter exit**: a daemon thread waiting on an Event —
  never `time.sleep` in a loop, which would park `close()` for up to a 30-minute backoff.

## 3. The server key IS a secret (server-contract-v1, ADR-0015)

The explicit inversion of the client SDKs' "the SDK key is not a secret":

- The raw `ffs_` key lives in memory and goes out on the `Authorization` header — nowhere
  else, ever. Never a log line, an exception message, a cache file, or a repr.
- The only loggable form is the prefix: `ffs_<env>_` plus six characters.
- Test fixtures use short, low-entropy keys (`ffs_dev_k`). A realistic-looking `ffs_` value
  in this repo SHOULD page a secret scanner — never commit one, never allowlist a finding;
  shorten the fixture.

## 4. Context keys and tags are the customer's data (Founding §7.3)

Never logged, never persisted (the opt-in cache holds the RULESET envelope, never contexts),
never transmitted. The context key is an **opaque string** — never validated against the
client SDKs' `dev_`/`sim_` shape, never trimmed or normalised: the bucket hashes exactly the
UTF-8 bytes given, or cohorts flip between components.

## 5. Zero runtime dependencies (ADR-0020)

`pyproject.toml`'s `dependencies` list is **empty, and that emptiness is the gate** — CI
asserts it. Everything the SDK needs is stdlib: `urllib.request`, `hashlib`, `json`,
`base64`, `threading`, `tempfile`, `os`. The `dev` extra is tooling and never ships. A
runtime dependency is a supply-chain decision the user owns: **ask, don't add.**

## 6. Network surface

`GET /v1/server/ruleset?sv=1` with `Authorization`, `Accept`, and `If-None-Match` — nothing
else, ever. No SDK-version header, no telemetry: an undocumented header is an additive
contract change that goes through a backend ADR. Poll 60 s default, floored at the
contract's 30; backoff cap 1800 s with ±20% jitter ON THE SUCCESS PATH TOO; redirects
refused (an opener with no redirect handler — a followed redirect could replay the
Authorization header); bodies capped at 1 MiB.

## 7. Concurrency model (ADR-0020)

The snapshot is published by a single attribute assignment (atomic under the GIL, and a
plain reference swap under free-threading); getters read it ONCE into a local and evaluate
against that. Mutable diagnostic state sits behind one lock the evaluation path never
takes. **Do not add a lock to the read path "for safety" — the lock-free read IS the
design** (Go's atomic.Pointer, translated).

## 8. Workflow

- Default branch `development`; all changes via PR; squash merge, linear history, `(#N)` on
  every development commit. CI is the merge gate — we cannot recall a shipped SDK.
- Commits and PRs carry FortressFlag authorship, never a personal identity: local commits
  as `FortressFlag <noreply@fortressflag.com>`; PRs opened and merged via the
  `fortressflag` GitHub App.
- **The public API (`src/fortressflag/__init__.py`'s `__all__`) and the consumed contract
  are backward-compatibility sacred** (Founding §5, §8.3).
- Local gate, identical to CI:
  `ruff check . && ruff format --check . && mypy && python -m pytest`.
- `src/fortressflag/_vectors/*.json` (evaluation, buckets, signing) are verbatim vendored copies; the canonical home is
  `FortressFlag_Standards/vectors/`. A vector change is a wire-contract change arriving via
  a backend ADR — never a test fix, and never edited only here.
