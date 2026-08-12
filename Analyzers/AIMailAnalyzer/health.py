#!/usr/bin/env python3
"""
Standalone probe for the AIMailAnalyzer *thin client* image (P7).

ai_mail_classifier.py stopped loading models itself - it's now an HTTP
client to inference_server/, which owns the vectorizer + both model
variants and stays running (see that folder's own docstring for why: Cortex
spawns this image fresh per job, so anything it loaded itself was reloaded
from disk on every single mail; the persistent server loads once instead).

What this script does:
  * Confirms this image's own deps (cortexutils, requests) import cleanly -
    the only two things ai_mail_classifier.py actually needs now.
  * Best-effort pings the inference server's /health endpoint and reports
    which variants it has loaded - informational only, never fails the
    probe on its own: this image can be smoke-tested in isolation (CI)
    without the server running.

Use cases:
  * CI / container build smoke test:
        docker run --rm --entrypoint python <image> AIMailAnalyzer/health.py
  * Operator probe after pushing a new image
"""

from __future__ import annotations

import os
import sys
import traceback

INFERENCE_SERVER_URL = os.environ.get("INFERENCE_SERVER_URL", "http://172.17.0.1:8090")


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
