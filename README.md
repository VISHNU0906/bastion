# Bastion

**Bastion is monitoring and alerting on security infrastructure, done the SRE way:** it
collects security signals, exposes them as Prometheus metrics, defines security
SLOs with multi-burn-rate alerting, ships Grafana dashboards, and turns
security-SLO breaches into tracked incidents with MTTD/MTTR.

Most security tooling tells you *what's wrong right now*. Bastion tells you
*whether your security posture is meeting a target over time, and pages you —
fast and accurately — when it isn't*. It applies the reliability math SRE teams
already use for uptime (SLOs, error budgets, burn-rate alerts) to **security**
signals: certificate health, security-header coverage, dependency CVEs, auth
failures, and runtime detections.

---

## Security SLOs, error budgets, and MTTD in four sentences

- A **security SLO** is a measured target for a security signal — e.g. "99% of
  critical detections are detected within 5 minutes" — instead of a vibe or a
  quarterly audit.
- An **error budget** is the small amount of "bad" the SLO tolerates (a 99.9%
  target allows 0.1%), which reframes security from "never fail" to "fail less
  than X and react fast when you're burning the budget too quickly."
- **MTTD (mean time to detect)** is the time from when something bad *happened*
  to when you *noticed* it; **MTTR (mean time to resolve)** is from when an
  incident opened to when it was fixed — Bastion measures both as real deltas.
- Bastion alerts using the **multi-window, multi-burn-rate** method from the
  Google SRE Workbook, so your pager fires on genuine, sustained budget burn —
  not on every transient blip.

A deeper write-up (including why security SLIs need different math per shape) is
in [`docs/SECURITY_SLOS.md`](docs/SECURITY_SLOS.md).

---

## Run the demo in 3 commands

```bash
# 1. Start the whole stack: Bastion exporter + Prometheus + Alertmanager +
#    Grafana + a security-event generator (secgen).
docker compose -f deploy/docker-compose.yml up --build
```

```bash
# 2. Nothing else to do — secgen is already posting synthetic Falco-style
#    detections (with backdated event times, so MTTD is real) and auth-failure
#    bursts. Watch it work:
docker compose -f deploy/docker-compose.yml logs -f secgen
```

```bash
# 3. Open Grafana and watch the security SLOs react.
open http://localhost:3000      # login admin / admin
```

In Grafana you'll see two dashboards (folder **Bastion**):

- **Security Posture** — cert days-to-expiry, header coverage, CVE counts, auth
  failure ratio, detection rate, **MTTD**, and open incidents.
- **Security SLOs** — error-budget-remaining gauges, **burn rate**, and the SLI
  error ratio per window for each SLO.

Every ~6 cycles `secgen` fires a *burst*: a critical detection with a large
detection latency (MTTD climbs, an incident auto-opens) and a spike of auth
failures (the auth-failure-ratio SLO burns budget). Then it calms down so you can
watch the error budget recover. Other UIs while the stack is up:

- Prometheus: <http://localhost:9090> (the **Alerts** tab shows the *fast*
  burn-rate alerts — 1h/5m and 6h/30m — go pending → firing during a burst; the
  slow 24h/3d alerts need a longer-running Prometheus, see Honest limitations)
- Alertmanager: <http://localhost:9093>
- Bastion: <http://localhost:9300/status> and <http://localhost:9300/metrics>

> **No Docker?** Everything except the dashboards runs offline:
> `make generate` writes the Prometheus rules + dashboard JSON to `out/`,
> `make show` prints the computed burn-rate thresholds, `make test` runs the
> full suite, and `make run` starts just the exporter so you can `curl` the
> ingest API.

---

## What Bastion collects

Each collector runs on every Prometheus scrape, is wrapped in error isolation
(one failure never breaks the scrape — it sets `bastion_collector_up=0`), and
degrades gracefully offline.

| Collector         | Signal                                   | Key metric(s)                                            |
|-------------------|------------------------------------------|----------------------------------------------------------|
| `tls_cert`        | TLS cert days-to-expiry per endpoint     | `bastion_tls_cert_expiry_days`, `bastion_tls_cert_valid` |
| `http_headers`    | HSTS / CSP / X-Frame / X-Content-Type    | `bastion_security_header_present`, `..._coverage_ratio`  |
| `dependency_cves` | known CVEs for a requirements file (OSV) | `bastion_dependency_vulns`, `..._critical_over_age`      |
| `auth_failures`   | auth-failure rate (log or pushed)        | `bastion_auth_failures_total`, `..._attempts_total`      |
| `detections`      | runtime-security detections (Falco-style)| `bastion_security_detections_total`, `..._mttd_seconds`  |

Push signals arrive via the ingest API (see below); the rest are pulled on
scrape.

---

## Architecture

```
        SECURITY SIGNALS                  BASTION                       SRE OUTPUTS
  ┌───────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
  │ TLS certs             │      │  collectors (scrape) │      │  Prometheus          │
  │ HTTP security headers │─────▶│  ┌────────────────┐  │      │  ┌────────────────┐  │
  │ dependency CVEs (OSV) │ pull │  │ tls / headers  │  │      │  │ recording +    │  │
  │ auth logs             │      │  │ cves / auth    │  │      │  │ alerting rules │  │
  └───────────────────────┘      │  └────────────────┘  │      │  └────────────────┘  │
                                 │                      │      │         │            │
  ┌───────────────────────┐ push │  ┌────────────────┐  │  /metrics      ▼            │
  │ Falco / Wazuh / EDR   │─────▶│  │ detections +   │──┼─────▶│  burn-rate /        │
  │ (POST /ingest/detection)│    │  │ MTTD engine    │  │ scrape│  threshold alerts   │
  └───────────────────────┘      │  └────────────────┘  │      │         │            │
                                 │           │          │      └─────────┼────────────┘
                                 │           ▼          │                │ Alertmanager
       slos.example.yaml ───────▶│  ┌────────────────┐  │     /webhook/  ▼ breach
       (security SLO defs)       │  │ SLO generator  │──┼────▶ rules+dashboard         │
                                 │  │ (burn-rate)    │  │                │            │
                                 │  └────────────────┘  │                ▼            │
                                 │  ┌────────────────┐  │      ┌──────────────────────┐
                                 │  │ incident engine│◀─┼──────│  incident (severity, │
                                 │  │ MTTD / MTTR    │  │      │  runbook, MTTD/MTTR)  │
                                 │  └────────────────┘  │      └──────────────────────┘
                                 └──────────────────────┘                │
                                                                         ▼
                                                                ┌──────────────────────┐
                                                                │  Grafana dashboards  │
                                                                │  posture + SLOs      │
                                                                └──────────────────────┘
```

The loop end to end: **signal → metric → SLO → burn-rate/threshold alert →
incident → Grafana.**

---

## Security-SLO YAML schema

SLOs live in [`slos.example.yaml`](slos.example.yaml). The interesting part is
that security SLIs come in **four shapes**, and Bastion generates different rules
for each (using `rate()` only where it's mathematically valid):

```yaml
group_name: bastion_security_slos
slos:
  # ratio — counter-rate ratio (auth failures / attempts). Burn-rate over rate().
  - name: Auth Failure Ratio
    objective: 99            # < 1% of attempts may fail
    window: 30d
    sli:
      type: ratio
      error: bastion_auth_failures_total
      total: bastion_auth_attempts_total

  # freshness — point-in-time gauge ratio. Uses avg_over_time, NOT rate().
  - name: Certificate Freshness
    objective: 99.9          # 99.9% of certs valid > 14 days
    window: 30d
    sli:
      type: freshness
      good: bastion_tls_cert_valid     # a 0/1 gauge (1 = compliant)

  # latency_ratio — fraction meeting a latency target (MTTD reframed). Burn-rate.
  - name: Detection MTTD
    objective: 99            # 99% of critical detections detected within 5m
    window: 30d
    sli:
      type: latency_ratio
      good: bastion_detection_latency_seconds_bucket{le="300.0",priority="Critical"}
      total: bastion_detection_latency_seconds_count{priority="Critical"}

  # threshold — a hard invariant with NO error budget. One comparison alert.
  - name: Critical CVE Age
    window: 30d
    sli:
      type: threshold
      metric: bastion_dependency_critical_over_age
      comparison: ">"
      limit: 0
      severity: page
```

Generate the artifacts:

```bash
bastion generate -f slos.example.yaml -o out/   # writes rules YAML + dashboard JSON
bastion validate -f slos.example.yaml           # validate without generating
bastion show     -f slos.example.yaml           # print computed burn-rate thresholds
```

| `sli.type`      | Required fields                          | Generates                                  |
|-----------------|------------------------------------------|--------------------------------------------|
| `ratio`         | `total` + (`good` or `error`), `objective`| recording rules + 4 burn-rate alerts       |
| `freshness`     | `good` (a boolean gauge), `objective`     | `avg_over_time` recording rules + 4 alerts |
| `latency_ratio` | `good` + `total`, `objective`             | recording rules + 4 burn-rate alerts       |
| `threshold`     | `metric` + `comparison` + `limit`         | one comparison alert (no error budget)     |

---

## Metrics reference

| Metric                                          | Type      | Labels            | Meaning                                            |
|-------------------------------------------------|-----------|-------------------|----------------------------------------------------|
| `bastion_tls_cert_expiry_days`                  | gauge     | endpoint, host    | days until the cert expires (negative = expired)   |
| `bastion_tls_cert_valid`                        | gauge     | endpoint, host    | 1 if > warning_days left (freshness SLI)           |
| `bastion_security_header_present`               | gauge     | target, header    | 1 if a security header is present                  |
| `bastion_security_header_coverage_ratio`        | gauge     | target            | fraction of required headers present               |
| `bastion_dependency_vulns`                      | gauge     | severity          | known CVE count by severity                         |
| `bastion_dependency_oldest_critical_age_days`   | gauge     | —                 | age of the oldest unpatched critical/high CVE      |
| `bastion_dependency_critical_over_age`          | gauge     | —                 | criticals older than the limit (threshold SLI)     |
| `bastion_auth_failures_total`                   | counter   | source            | auth failures observed                              |
| `bastion_auth_attempts_total`                   | counter   | source            | auth attempts observed                              |
| `bastion_auth_failure_rate`                     | gauge     | source            | failures/sec over the rolling window               |
| `bastion_security_detections_total`             | counter   | rule, priority    | runtime-security detections ingested               |
| `bastion_detection_latency_seconds`             | histogram | priority          | per-event detection latency (MTTD basis)           |
| `bastion_detection_mttd_seconds`                | gauge     | priority          | rolling mean time to detect                        |
| `bastion_incidents_total`                       | counter   | severity, kind    | incidents opened                                   |
| `bastion_incidents_open`                        | gauge     | severity          | currently-open incidents                           |
| `bastion_incident_mttr_seconds`                 | histogram | —                 | time to resolve                                    |
| `bastion_collector_up`                          | gauge     | collector         | 1 if the collector ran without error               |

---

## Ingest & status API

The exporter (FastAPI) serves both metrics and push endpoints:

| Endpoint                 | Method | Purpose                                                    |
|--------------------------|--------|------------------------------------------------------------|
| `/metrics`               | GET    | Prometheus exposition (runs all collectors)                |
| `/ingest/detection`      | POST   | push a Falco-style detection (single or list)              |
| `/ingest/auth`           | POST   | push an auth failures/attempts batch                       |
| `/webhook/breach`        | POST   | Alertmanager hook: open an incident on an SLO breach       |
| `/healthz`               | GET    | liveness                                                   |
| `/status`                | GET    | JSON: collectors, detections, open incidents               |

Example — push a detection with a backdated event time so MTTD is real:

```bash
curl -X POST http://localhost:9300/ingest/detection \
  -H 'content-type: application/json' \
  -d '{"rule":"Terminal shell in container","priority":"Critical","time":'"$(($(date +%s)-120))"'}'
# -> 202, latency_seconds ~120, and a critical incident is auto-opened.
```

---

## Configuration

Runtime config (targets, thresholds, enabled collectors) lives in
[`config.example.yaml`](config.example.yaml); runbook links per incident kind
live in [`runbooks.example.yaml`](runbooks.example.yaml). Every section has
sane defaults, so a partial config still runs.

---

## Development

```bash
make install   # runtime + test deps
make test      # 100+ offline tests (network mocked; no Docker needed)
make generate  # write rules + dashboard to out/
make run       # run the exporter locally
```

Tests are fully offline: collectors are network-mocked, the burn-rate math is
asserted against the SRE Workbook's known values, detection ingest + MTTD and the
breach→incident path are exercised end to end via FastAPI's in-process test
client.

---

## Honest limitations

- **Demo timescale vs. window sizes.** The generated rules include 24h/3d long
  windows and a 30-day budget gauge, but the demo's Prometheus retention is 2h.
  In a short demo run only the *fast* windows (1h/5m, 6h/30m) populate, so the
  fast burn-rate alerts and the posture panels react; the slow-burn (24h/3d)
  alerts and the 30d budget gauge need a longer-running Prometheus to be
  meaningful.
- **Incidents accumulate in the demo.** Nothing auto-resolves incidents during
  the demo, so `bastion_incidents_open` only climbs and the MTTR histogram stays
  empty at runtime. MTTR (`resolve()`) is unit-tested; it's just not driven by
  the synthetic generator. Resolve via the API/engine to exercise it.
- **CVE severity coverage depends on OSV detail records.** Counts come from
  OSV.dev; Bastion enriches per-vuln severity/age from the single-vuln endpoint
  (bounded by `max_detail_lookups`). Advisories without a parseable
  `database_specific.severity` or CVSS score land in the `UNKNOWN` bucket.
- **Rules validated as YAML + against the SRE Workbook's known values, not via
  `promtool`.** The expressions are well-formed PromQL and the burn-rate math is
  unit-tested against canonical numbers, but they have not been run through
  Prometheus's own `promtool check rules`.

---

## Roadmap

- **Falco / Wazuh native integration** — first-class adapters for their webhook
  payloads (Bastion already accepts the Falco-style shape).
- **CloudWatch security metrics** — an exporter that pulls GuardDuty / Security
  Hub / Config findings into Bastion SLIs.
- **More SLIs** — secrets-scanning freshness, IAM key age, MFA coverage, patch
  latency, WAF block ratio.
- **Incident sinks** — PagerDuty / Opsgenie / Slack receivers off the incident
  engine, with the runbook link attached.
- **SLO history** — persist error-budget burn over time for reporting
  (security-SLO compliance %, MTTD/MTTR trends).

---

## License

MIT © 2026 Vishnu Kosuri. See [LICENSE](LICENSE).
