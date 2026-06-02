# Security SLOs, error budgets, and MTTD

This is the "why" behind Bastion. It explains, in plain English, what it means
to apply SRE reliability math to *security* signals — and the one design
decision that makes it real rather than a buzzword: **security SLIs are not all
the same shape, so the alerting math has to branch on the shape.**

---

## Why security needs SLOs

Reliability SRE answers "is the service up enough?" with a number you commit to:
*99.9% of requests succeed*. Security teams ask the same kind of question all
day — "are our certs healthy?", "are we detecting attacks fast enough?", "are we
patching criticals in time?" — but usually answer it with vibes, a spreadsheet,
or a once-a-quarter audit.

An SLO turns that into a measured, alertable target. "Are we detecting attacks
fast enough?" becomes **"99% of critical detections are detected within 5
minutes, measured continuously."** Now it has a number, a trend, and an alert
when it slips — the same rigor SRE already brings to uptime.

## What a "security error budget" means

If your target is *99.9% of certs valid for more than 14 days*, then 0.1% of the
time a cert is allowed to slip inside that window. That 0.1% is your **error
budget** — the amount of "bad" the objective explicitly tolerates. You don't aim
for zero (zero is impossible and infinitely expensive); you aim for the target,
and you *spend* the budget on the inevitable messy reality of running systems.

The budget reframes security work from "never fail" to "fail less than X, and
react fast when you're burning the budget faster than you should." That is a
much healthier, much more operable goal.

> One important exception: some security targets genuinely are **zero** — e.g.
> "no critical CVE older than 7 days." There is no error budget for an invariant
> that must be exactly zero. Bastion handles those as a separate kind of SLO (a
> `threshold`), with a simple "this should never be true" alert instead of
> burn-rate math. Forcing a zero-budget invariant through burn-rate alerting
> would be mathematically meaningless, and a lot of security-SLO tooling gets
> this wrong.

## MTTD vs MTTR

Two different clocks, both central to security operations:

- **MTTD — Mean Time To Detect.** From when something bad *happened* to when you
  *noticed*. This is a detection-speed metric. Bastion measures it as a real
  delta: every detection carries the time the event occurred (`event_time`) and
  the time Bastion received it (`detection_time`); the latency is
  `detection_time - event_time`, and MTTD is the rolling mean of those
  latencies. (If you only recorded "now" when a webhook arrived, MTTD would
  always be ~0 and tell you nothing — so the event time must be real.)
- **MTTR — Mean Time To Resolve.** From when an incident was *opened* to when it
  was *resolved*. This is a response-speed metric. Bastion measures it when an
  incident the engine opened gets resolved.

MTTD is "how fast do we see it?"; MTTR is "how fast do we fix it?". Bastion
exposes both, and turns MTTD into a budgeted SLO (below).

## Multi-window, multi-burn-rate alerting (the Google SRE method)

A naive SLO alert fires when the error rate crosses the budget line. That is
either too noisy (a 30-second blip pages you) or too slow (you wait an hour to
confirm an outage). The Google SRE Workbook's fix is **multi-window,
multi-burn-rate** alerting:

- **Burn rate** is how fast you're spending the budget. `1x` spends the whole
  window's budget exactly on time; `14.4x` would spend a 30-day budget in ~2
  days — an emergency.
- Each alert requires **two windows to breach at once**: a long window (is this
  real?) AND a short window (is it still happening right now?). The long window
  kills false alarms; the short window makes the alert reset quickly once the
  burn stops.
- Bastion generates the canonical four alerts: fast pages at **14.4x (1h/5m)**
  and **6x (6h/30m)**, slower tickets at **3x (24h/2h)** and **1x (3d/6h)**.

The threshold that goes into each alert is **window-independent**:

```
threshold = burn_rate * (1 - objective)
```

For a 99.9% objective (budget `0.001`): `14.4 → 0.0144`, `6 → 0.006`,
`3 → 0.003`, `1 → 0.001`. These exact numbers are unit-tested in
`tests/test_burnrate.py`, so the math is verifiable by hand, not asserted on
faith. (The math itself is vendored, unchanged, from the sibling Vigil SLO
tool — same proven engine, applied here to security SLIs.)

## The part most security-SLO tools get wrong: SLI shape

Burn-rate alerting assumes an **event-rate ratio** SLI — bad events over total
events, measured with `rate()` over a window. But security SLIs come in several
shapes, and using `rate()` on the wrong shape produces nonsense PromQL. Bastion
picks the right generation path per SLI `type`:

| SLI type        | Shape                          | Example                                   | How rules are built                                         |
|-----------------|--------------------------------|-------------------------------------------|-------------------------------------------------------------|
| `ratio`         | counter-rate ratio             | auth failures / attempts < 1%             | `rate(error[w]) / rate(total[w])` → burn-rate alerts        |
| `freshness`     | point-in-time **gauge** ratio  | 99.9% of certs valid > 14 days            | `1 - avg(avg_over_time(valid[w]))` → burn-rate alerts       |
| `latency_ratio` | fraction meeting a target      | 99% of critical detections detected < 5m  | `1 - rate(good[w]) / rate(total[w])` → burn-rate alerts     |
| `threshold`     | hard invariant (zero budget)   | 0 critical CVEs older than 7 days         | `metric > limit` → **one** comparison alert, no burn-rate   |

The key correctness points:

- **`freshness` never uses `rate()`.** A cert-validity gauge is a 0/1 state, not
  an event counter. `rate()` on a gauge is meaningless; the right operator is
  `avg_over_time` over the window (the fraction of time it was compliant),
  averaged across the fleet.
- **`threshold` has no error budget.** When the target is exactly zero, there is
  nothing to burn. Bastion emits a single "should never be true" alert.
- **MTTD is reframed as `latency_ratio`.** Instead of alerting on a brittle mean
  ("MTTD < 5m"), Bastion measures *the fraction of critical detections detected
  within 5 minutes* and budgets it (≥ 99%). That makes a slow-detection trend
  burn an error budget and page through the same machinery as everything else,
  which is both more stable and more honest than thresholding a noisy average.

## Closing the loop: SLO breach → incident

When a burn-rate or threshold alert fires, Alertmanager calls Bastion's
`/webhook/breach`, and Bastion opens a tracked **incident** with a severity and a
runbook link. Critical runtime detections open incidents directly (capturing
their detection latency as the incident's MTTD). On resolve, Bastion records the
MTTR. So the whole chain is one system:

```
security signal → Prometheus metric → security SLO → burn-rate/threshold alert
              → incident (severity + runbook + MTTD) → resolve (MTTR)
```

That is the entire point of Bastion: **monitoring and alerting on security
infrastructure, done the SRE way.**
