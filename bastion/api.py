"""FastAPI surface for Bastion.

Routes:
  GET  /metrics            Prometheus exposition (runs all collectors).
  POST /ingest/detection   Push a Falco-style runtime-security detection.
  POST /ingest/auth        Push an auth-failure/attempt batch.
  POST /webhook/breach     Alertmanager-style hook: open an incident on a
                           security-SLO breach.
  GET  /healthz            Liveness probe (always 200 if the process is up).
  GET  /status             Human/JSON status: collectors, detections, incidents.

The app holds one shared :class:`Bastion` runtime so every request and every
scrape operate on the same in-memory state (detections, MTTD, incidents).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST

from bastion.runtime import Bastion


def create_app(bastion: Bastion | None = None) -> FastAPI:
    """Build the FastAPI app bound to a Bastion runtime (created if not given)."""
    runtime = bastion or Bastion()
    app = FastAPI(
        title="Bastion",
        description="SRE for security infrastructure — security signals, "
        "security SLOs, burn-rate alerts, and incidents.",
        version=runtime.status()["version"],
    )
    app.state.bastion = runtime

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/status")
    def status() -> dict[str, Any]:
        return app.state.bastion.status()

    @app.get("/metrics")
    def metrics() -> Response:
        body = app.state.bastion.render_metrics()
        return PlainTextResponse(body, media_type=CONTENT_TYPE_LATEST)

    @app.post("/ingest/detection")
    async def ingest_detection(request: Request) -> JSONResponse:
        payload = await request.json()
        # Accept either a single detection or a list (Falco can batch).
        items = payload if isinstance(payload, list) else [payload]
        results = []
        for item in items:
            try:
                detection, incident = app.state.bastion.ingest_detection(item)
            except ValueError as exc:
                return JSONResponse(status_code=422, content={"error": str(exc)})
            results.append(
                {
                    "rule": detection.rule,
                    "priority": detection.priority,
                    "latency_seconds": round(detection.latency_seconds, 3),
                    "incident_id": incident.id if incident else None,
                }
            )
        return JSONResponse(status_code=202, content={"ingested": len(results), "results": results})

    @app.post("/ingest/auth")
    async def ingest_auth(request: Request) -> JSONResponse:
        payload = await request.json()
        try:
            failures = int(payload.get("failures", 0))
            attempts = int(payload.get("attempts", failures))
            source = str(payload.get("source", "pushed"))
            app.state.bastion.ingest_auth(failures, attempts, source=source)
        except (ValueError, RuntimeError) as exc:
            return JSONResponse(status_code=422, content={"error": str(exc)})
        return JSONResponse(status_code=202, content={"failures": failures, "attempts": attempts})

    @app.post("/webhook/breach")
    async def webhook_breach(request: Request) -> JSONResponse:
        """Alertmanager-compatible-ish breach hook.

        Accepts either Bastion's simple shape ``{slo, burn_rate, severity}`` or
        an Alertmanager payload with ``alerts: [{labels: {...}}]``.
        """
        payload = await request.json()
        opened = []
        alerts = payload.get("alerts") if isinstance(payload, dict) else None
        if alerts:  # Alertmanager shape
            for alert in alerts:
                labels = alert.get("labels", {})
                if alert.get("status", "firing") != "firing":
                    continue
                inc = app.state.bastion.report_breach(
                    slo_name=labels.get("slo", labels.get("alertname", "unknown")),
                    burn_rate=float(labels.get("burn_rate", 1) or 1),
                    severity="critical" if labels.get("severity") == "page" else "high",
                )
                opened.append(inc.id)
        else:  # Bastion simple shape
            inc = app.state.bastion.report_breach(
                slo_name=str(payload.get("slo", "unknown")),
                burn_rate=float(payload.get("burn_rate", 1)),
                severity=str(payload.get("severity", "high")),
            )
            opened.append(inc.id)
        return JSONResponse(status_code=202, content={"incidents_opened": opened})

    return app
