# FortressFlag Python SDK

FortressFlag's **Python server SDK** (backend ADR-0020): pure stdlib, zero dependencies.
Polls the server data plane's ruleset export with an `ffs_` server key and evaluates flags
**locally, in-process** — no network hop per flag check.

```python
import fortressflag

client = fortressflag.create(fortressflag.Configuration(key=os.environ["FF_SERVER_KEY"]))
# ^ the one place the SDK raises
client.start(timeout=15.0)   # returns at the first ruleset (or the deadline); never fatal
enabled = client.bool_value(
    "dark-mode",
    fortressflag.Context(key="user-42", tags={"cohort": "beta"}),
    False,
)
client.close()
```

It implements
[`FortressFlag_Standards/contracts/server-contract-v1.md`](https://github.com/FortressFlag/FortressFlag_Standards/blob/development/contracts/server-contract-v1.md)
— owned by `FortressFlag_Backend`, changed only via ADRs there. Zero runtime dependencies;
after construction, evaluation never raises. Every ruleset carries an Ed25519 signature that
the SDK verifies against FortressFlag's production key before a single flag is served (backend
ADR-0025) — the verifier is vendored, so the dependency list stays empty. Against a local
backend that runs without signing keys, pass `signature=fortressflag.SIGNATURE_DISABLED`
explicitly. See `CLAUDE.md` for the rules this repo holds itself to.

**The `ffs_` server key is a genuine secret** — treat it like a database password. Store it
in an environment variable or a secret manager, never in code or logs.
