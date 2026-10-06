#!/usr/bin/env python3
"""Probe for the client image: checks that cortexutils and requests import,
then pings the inference server's /health. An unreachable server is reported
but is not a failure, so the image can be smoke-tested without it:

    docker run --rm --entrypoint python <image> AiMailPublicAnalyzer/health.py
"""
from __future__ import annotations

import os
import sys
import traceback

INFERENCE_SERVER_URL = os.environ.get("AI_PUBLIC_INFERENCE_SERVER_URL", "http://172.17.0.1:8091")


def main() -> int:
    try:
        import cortexutils.analyzer  # noqa: F401
        import requests
    except Exception as exc:
        print(f"import_error: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    try:
        resp = requests.get(f"{INFERENCE_SERVER_URL}/health", timeout=5)
        resp.raise_for_status()
        print(f"inference_server: reachable, {resp.json()}")
    except Exception as exc:
        print(f"inference_server: unreachable ({exc}) - informational only, not a failure here")

    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
