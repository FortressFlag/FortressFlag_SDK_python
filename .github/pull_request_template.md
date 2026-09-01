<!--
State non-obvious tradeoffs against the pillar order (Security → Compliance → Efficiency →
Cost). A PR that trades one for another says so out loud.
-->

## What & why

<!-- What changes, and the reason it exists. Link the ADR or plan when one applies. -->

## Compliance & security review

<!--
SOC 2 Type II is graded by sampling real changes and asking for evidence that review
happened; GDPR expects data-protection questions asked at design time. This SDK runs inside
customers' processes, holds a genuine secret, receives targeting rules, and is handed
context identifiers. Tick every box that applies — or tick the last one. A block with
nothing ticked is an unfinished PR.
-->

- [ ] **Server-key handling** — touches how the `ffs_` key is stored, sent, or could reach a log (ADR-0015)
- [ ] **Customer data** — context keys/tags: logged, persisted, or transmitted anywhere beyond evaluation (Founding §7.3)
- [ ] **Filesystem** — changes what the opt-in cache writes or where (ADR-0016)
- [ ] **Network surface** — what is sent, to where, how often (the contract names every header)
- [ ] **Host-process impact** — raises reaching the caller, threads blocking interpreter exit, blocking work on evaluation paths (Founding §8.1)
- [ ] **Public API** — `src/fortressflag/__init__.py`'s `__all__`; backward compatibility is sacred (Founding §8.3)
- [ ] **None of the above** — say why in one sentence

## Fallback behaviour

<!--
How does this change behave when everything is wrong? Address the three standing scenarios
where relevant: a cold start with no connectivity; a cache_path load after a long outage
(expiry unenforced); a revoked key mid-run.
-->

## Testing

<!-- The local gate is `ruff check . && ruff format --check . && mypy && python -m pytest`.
What did you verify beyond it, especially against a live backend, which CI cannot do? -->

## Tradeoffs

<!-- Or "none". -->
