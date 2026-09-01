"""§6's walkthrough vehicle. Run the backend stack locally (`make db-up migrate seed dev`
in FortressFlag_Backend), then, with no configuration at all: `python example/run.py`.

The seed key is committed deliberately and is low-entropy on purpose — it authenticates
against a laptop database and nothing else (CLAUDE.md §3's fixture rule).
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import fortressflag  # noqa: E402

SEED_KEY = "ffs_dev_seedseedseedseedseedseedseedseedseedseed000"


def env(name: str, fallback: str) -> str:
    value = os.environ.get(name, "")
    return value if value != "" else fallback


def main() -> int:
    try:
        client = fortressflag.create(
            fortressflag.Configuration(
                key=env("FF_SERVER_KEY", SEED_KEY),
                base_url=env("FF_BASE_URL", "http://localhost:8080"),
                cache_path=os.environ.get("FF_CACHE_PATH", ""),
            )
        )
    except fortressflag.MalformedKeyError as error:
        print(error, file=sys.stderr)
        return 1

    outcome = client.start(timeout=15.0)
    print(f"start: {outcome.value}")

    contexts = [
        fortressflag.Context(key="user-1", tags={"cohort": "beta"}),
        fortressflag.Context(key="user-3", tags={"cohort": "beta"}),
    ]
    flags = ["new-checkout-flow", "dark-mode", "beta-analytics"]

    try:
        while True:
            d = client.diagnostics()
            source = d.snapshot_source or "-"
            print(
                f"{time.strftime('%H:%M:%S')}  fetch={d.last_fetch_status} "
                f"failures={d.consecutive_failures} source={source} flags={d.flag_count}"
            )
            for ctx in contexts:
                values = "  ".join(f"{f}={client.bool_value(f, ctx, False)}" for f in flags)
                print(f"  {ctx.key}: {values}")
            time.sleep(10)
    except KeyboardInterrupt:
        client.close()
        print(f"diagnostics: {client.diagnostics()}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
