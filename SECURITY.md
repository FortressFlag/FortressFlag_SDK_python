# Security Policy

FortressFlag holds the switches that turn our customers' production behavior on and off. A
compromise of FortressFlag is a compromise of every customer that trusts us (Founding CLAUDE.md
§2.1). We would rather hear about a problem early and awkwardly than late and publicly.

## Reporting a vulnerability

**Use GitHub private vulnerability reporting:** open the repository's **Security** tab and choose
**Report a vulnerability**. This creates a private advisory that only maintainers can see, so a
report never sits in a public issue while it is still exploitable.

Please do not open a public issue, pull request, or discussion for a suspected vulnerability.

Helpful reports usually include: what you found, how to reproduce it, which component and version,
and what an attacker gets out of it. A rough report you send today beats a polished one you send
next month.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement that a human has read it | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix or documented mitigation for critical/high findings | 30 days from assessment |

These are targets for a small team, stated so you know when to chase us rather than assume
silence means indifference. If a target slips, we will tell you where the work stands.

## Scope

This repository is the **Python server SDK** — code that runs inside our customers' own server
processes, holds a genuine secret (the `ffs_` server key), receives the customer's targeting
rules, and is handed the customer's own context identifiers on every evaluation. Findings we
especially want to hear about:

- **The server key reaching anywhere but the `Authorization` header.** A log line, an exception
  message, a `repr`, a cache file. The only loggable form is the prefix (`ffs_<env>_` plus six
  characters); anything more is a finding.
- **Customer data leaving in-process evaluation.** Context keys and tags exist only as evaluation
  inputs — never logged, never persisted, never transmitted. Anything that widens that is serious.
- **Cache-file exposure.** The opt-in `cache_path` file holds only the last verified ruleset
  envelope's raw bytes, written atomically. Anything that stores more, or somewhere else, is a
  finding.
- **Host-process impact.** After construction the SDK must never raise to the caller, never exit
  the process, and never block interpreter exit (§8.1).
- **Ruleset or transport integrity** — anything letting an attacker feed the SDK a ruleset it
  should not accept, including a weakness in the vendored Ed25519 verifier (`_ed25519.py`) or the
  fail-closed default it enforces.

Two notes specific to this repo:

- **We cannot recall a shipped SDK.** A vulnerable version lives in customers' deployments until
  they upgrade and redeploy, on their schedule. That makes findings here longer-lived than in the
  control plane, and worth reporting even when they look minor.
- **The verifier is vendored, not a dependency.** The zero-dependency rule (ADR-0020) means the
  Ed25519 arithmetic lives in this repository and is reviewed here; a finding against it is ours to
  fix, not upstream's.

Other components live in their own repositories, each with this policy: `FortressFlag_Standards`
(the published contracts and vectors), the sibling SDKs (`FortressFlag_SDK_ios`,
`FortressFlag_SDK_android`, `FortressFlag_SDK_web`, `FortressFlag_SDK_go`, `FortressFlag_SDK_node`,
`FortressFlag_SDK_java`), `FortressFlag_Backend` (control plane), `FortressFlag_Frontend`
(dashboard), `FortressFlag_Infra` (infrastructure).

## Safe harbour

If you make a good-faith effort to follow this policy, we will not pursue legal action against you
for your research. Good faith means: you do not access, modify, or retain data belonging to anyone
but yourself; you do not degrade service for others; you stop when you have proven the issue rather
than exploring how far it goes; and you give us a reasonable chance to fix it before disclosing.

## Disclosure

We will credit reporters who want credit, and coordinate timing on a public advisory once a fix is
available. If a finding affects customer data, our obligations under GDPR — including the 72-hour
notification window for a personal-data breach — take precedence over any disclosure timeline
agreed here.
