"""Security-event generator for the Bastion demo.

Posts synthetic Falco-style runtime-security detections and pushes auth-failure
batches to a running Bastion exporter so the dashboards and burn-rate alerts
come alive without a real Falco/Wazuh feed.

Two things make the demo realistic:

  1. **Backdated detection times.** Each detection carries an ``event_time`` a
     few seconds-to-minutes in the PAST (the moment the activity occurred), so
     Bastion computes a real, positive detection latency -> a real MTTD. A demo
     that stamped "now" for both would show MTTD ~= 0, which is meaningless.

  2. **A periodic burst.** Every few cycles it fires a CRITICAL detection with a
     deliberately LARGE latency (slow detection), which both pushes MTTD up and
     auto-opens an incident, and pushes a spike of auth failures so the
     auth-failure-ratio SLO visibly burns. Then it calms down so you can watch
     the error budget recover.

Run standalone:
    python sample/secgen.py --url http://localhost:9300 --interval 5
"""

from __future__ import annotations

import argparse
import random
import time

import requests

# A small library of Falco-style rules with plausible priorities.
_RULES = [
    ("Read sensitive file untrusted", "Warning"),
    ("Write below etc", "Error"),
    ("Terminal shell in container", "Critical"),
    ("Outbound connection to C2", "Critical"),
    ("Sudo to root by unexpected user", "Error"),
    ("New kernel module loaded", "Notice"),
    ("Package management launched in container", "Warning"),
    ("Crypto mining process started", "Critical"),
]


def make_detection(now: float, burst: bool) -> dict:
    """Build one synthetic Falco-style detection payload.

    The ``event_time`` is backdated so detection latency (and therefore MTTD) is
    a real positive number. On a burst we choose a critical rule with a LARGE
    latency to drive MTTD up and trip the incident path.
    """
    if burst:
        rule, priority = random.choice(
            [r for r in _RULES if r[1] == "Critical"]
        )
        latency = random.uniform(360, 900)  # 6-15 min: a slow detection
    else:
        rule, priority = random.choice(_RULES)
        latency = random.uniform(2, 120)  # 2s-2min: healthy detection speed

    event_time = now - latency
    return {
        "rule": rule,
        "priority": priority,
        "time": event_time,  # when it happened (backdated)
        "output": f"{rule} (synthetic demo event, latency ~{latency:.0f}s)",
    }


def post_detection(base_url: str, payload: dict, timeout: float = 5.0) -> None:
    requests.post(f"{base_url}/ingest/detection", json=payload, timeout=timeout)


def post_auth(base_url: str, failures: int, attempts: int, timeout: float = 5.0) -> None:
    requests.post(
        f"{base_url}/ingest/auth",
        json={"failures": failures, "attempts": attempts, "source": "secgen"},
        timeout=timeout,
    )


def run(base_url: str, interval: float, burst_every: int) -> None:
    """Continuously feed the exporter until interrupted."""
    print(f"secgen -> {base_url} every {interval}s (burst every {burst_every} cycles)")
    cycle = 0
    while True:
        cycle += 1
        burst = burst_every > 0 and cycle % burst_every == 0
        now = time.time()
        try:
            # 1-3 detections per cycle; a burst guarantees a critical one.
            for _ in range(random.randint(1, 3)):
                post_detection(base_url, make_detection(now, burst=False))
            if burst:
                post_detection(base_url, make_detection(now, burst=True))

            # Auth traffic: mostly healthy, with a failure spike on a burst.
            attempts = random.randint(20, 50)
            failures = random.randint(0, 1) if not burst else random.randint(8, 20)
            post_auth(base_url, failures=failures, attempts=attempts)

            tag = "BURST" if burst else "ok"
            print(f"cycle {cycle} [{tag}] auth {failures}/{attempts} failures")
        except requests.RequestException as exc:
            print(f"cycle {cycle}: exporter not reachable yet ({exc})")
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bastion demo security-event generator")
    parser.add_argument("--url", default="http://localhost:9300", help="Bastion exporter base URL")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between cycles")
    parser.add_argument("--burst-every", type=int, default=6, help="fire a critical+auth burst every N cycles (0=never)")
    args = parser.parse_args(argv)
    try:
        run(args.url, args.interval, args.burst_every)
    except KeyboardInterrupt:
        print("\nsecgen stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
