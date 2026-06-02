"""Bastion exporter entrypoint.

Runs the FastAPI app (which serves /metrics, the ingest webhook, /healthz, and
/status) under uvicorn. Reads the config path from the BASTION_CONFIG env var or
``--config``; falls back to all-defaults if none is given.

    python -m bastion.exporter --config config.example.yaml
    python -m bastion.exporter            # all defaults, port 9300

Importing this module is side-effect-free; everything happens in ``main()`` so
tests can ``from bastion.exporter import build_runtime`` without starting a
server.
"""

from __future__ import annotations

import argparse
import logging
import os

from bastion.api import create_app
from bastion.config import BastionConfig, default_config, load_config
from bastion.runtime import Bastion


def build_runtime(config_path: str | None) -> Bastion:
    """Load config (or defaults) and build a wired Bastion runtime."""
    config: BastionConfig
    if config_path:
        config = load_config(config_path)
    else:
        config = default_config()
    return Bastion(config)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bastion-exporter",
        description="Bastion exporter — serves security metrics, the detection "
        "ingest webhook, /healthz and /status.",
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("BASTION_CONFIG"),
        help="path to a Bastion config YAML (default: $BASTION_CONFIG or built-in defaults)",
    )
    parser.add_argument("--host", default=None, help="override the bind host")
    parser.add_argument("--port", type=int, default=None, help="override the bind port")
    parser.add_argument(
        "--log-level", default=os.environ.get("BASTION_LOG_LEVEL", "info"),
        help="logging level (debug/info/warning/error)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    runtime = build_runtime(args.config)
    host = args.host or runtime.config.exporter_host
    port = args.port or runtime.config.exporter_port

    app = create_app(runtime)

    import uvicorn

    logging.getLogger("bastion").info("Bastion exporter listening on %s:%s", host, port)
    uvicorn.run(app, host=host, port=port, log_level=args.log_level)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
