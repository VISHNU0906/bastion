"""Bastion command-line interface.

    bastion generate -f slos.example.yaml -o out/   # rules + dashboard
    bastion validate -f slos.example.yaml           # check the SLO YAML
    bastion show     -f slos.example.yaml           # print computed thresholds
    bastion serve    --config config.example.yaml   # run the exporter

Uses only the standard-library ``argparse`` for generate/validate/show so those
commands have no third-party dependency beyond generation itself; ``serve``
delegates to the exporter (which needs FastAPI/uvicorn).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from bastion import __version__
from bastion.slo.burnrate import burn_rate_alerts
from bastion.slo.generate import generate
from bastion.slo.model import load_config


def _cmd_generate(args: argparse.Namespace) -> int:
    config = load_config(args.file)
    written = generate(config, args.out)
    print(f"Loaded {len(config.slos)} security SLO(s) from {args.file}")
    for name, path in written.items():
        print(f"  wrote {name:9s} -> {path}")
    print(
        "Done. Mount bastion_security_rules.yaml into Prometheus and import the "
        "dashboard JSON into Grafana."
    )
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    config = load_config(args.file)
    print(f"OK: {args.file} is valid ({len(config.slos)} security SLO(s)).")
    for slo in config.slos:
        if slo.is_burn_rate:
            print(f"  - {slo.name} [{slo.sli_type}] {slo.objective}% / {slo.window}")
        else:
            print(f"  - {slo.name} [threshold] {slo.threshold_expr()}")
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    config = load_config(args.file)
    for slo in config.slos:
        if not slo.is_burn_rate:
            print(f"\n{slo.name}  [threshold over {slo.window}]")
            print(f"  invariant: alert when  {slo.threshold_expr()}")
            print(f"  (hard invariant -- no error budget; target value is the limit)")
            continue
        print(f"\n{slo.name}  [{slo.sli_type}, {slo.objective}% over {slo.window}]  "
              f"budget={slo.error_budget:.4g}")
        print(f"  SLI: error_ratio[1h] = {slo.error_ratio_expr('1h')}")
        print("  burn-rate alerts:")
        header = (
            f"    {'severity':8s} {'burn':>6s} {'long':>5s} {'short':>6s} "
            f"{'threshold':>12s} {'budget/win':>10s}"
        )
        print(header)
        for a in burn_rate_alerts(slo.objective):
            print(
                f"    {a.severity:8s} {a.burn_rate:6g} {a.long_window:>5s} "
                f"{a.short_window:>6s} {a.threshold:12.6f} {a.budget_consumed*100:9.1f}%"
            )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    # Imported lazily so generate/validate/show don't require FastAPI/uvicorn.
    from bastion.exporter import main as exporter_main

    serve_argv: list[str] = []
    if args.config:
        serve_argv += ["--config", str(args.config)]
    if args.host:
        serve_argv += ["--host", args.host]
    if args.port:
        serve_argv += ["--port", str(args.port)]
    return exporter_main(serve_argv)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bastion",
        description="Bastion - SRE for security infrastructure. Generate "
        "multi-burn-rate security-SLO rules + a Grafana dashboard, and run the "
        "security-metrics exporter.",
    )
    parser.add_argument("--version", action="version", version=f"bastion {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate", help="generate Prometheus rules + Grafana dashboard")
    p_gen.add_argument("-f", "--file", required=True, type=Path, help="security-SLO YAML")
    p_gen.add_argument("-o", "--out", default=Path("out"), type=Path, help="output directory")
    p_gen.set_defaults(func=_cmd_generate)

    p_val = sub.add_parser("validate", help="validate a security-SLO YAML config")
    p_val.add_argument("-f", "--file", required=True, type=Path, help="security-SLO YAML")
    p_val.set_defaults(func=_cmd_validate)

    p_show = sub.add_parser("show", help="print computed thresholds per SLO")
    p_show.add_argument("-f", "--file", required=True, type=Path, help="security-SLO YAML")
    p_show.set_defaults(func=_cmd_show)

    p_serve = sub.add_parser("serve", help="run the Bastion exporter (metrics + ingest API)")
    p_serve.add_argument("--config", type=Path, help="Bastion runtime config YAML")
    p_serve.add_argument("--host", help="override bind host")
    p_serve.add_argument("--port", type=int, help="override bind port")
    p_serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
