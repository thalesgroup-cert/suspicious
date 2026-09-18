#!/usr/bin/env python3
"""
Standalone probe for the AiMailPublicAnalyzer thin client image.

Confirms this image's own deps (cortexutils, requests) import cleanly, and
best-effort pings the inference server's /health endpoint - informational
only, never fails the probe on its own: this image can be smoke-tested in
isolation (CI) without the server running.

Use cases:
  * CI / container build smoke test:
        docker run --rm --entrypoint python <image> AiMailPublicAnalyzer/health.py
  * Operator probe after pushing a new image
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
