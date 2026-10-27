#!/usr/bin/env python3
"""
Standalone probe for the AIMailAnalyzer *thin client* image (P7).

ai_mail_classifier.py no longer loads models itself - it is an HTTP client to
inference_server/, which owns the vectorizer + both model variants and stays
running (see that folder's docstring for why: Cortex spawns this image fresh
per job, so anything it loaded itself was reloaded from disk on every single
mail; the persistent server loads once instead).

What this script does:
  * Confirms this image's own deps (cortexutils, requests) import cleanly -
    the only two things ai_mail_classifier.py needs now.
  * Pings the inference server's /health endpoint and prints which variants
    and models it has loaded. By default that is informational only, so the
    image can be smoke-tested in isolation (CI) without the server running.
  * With --require-server (or INFERENCE_REQUIRE_SERVER=1) an unreachable or
    not-ready server is a failure (exit 1). Use that as the operator probe
    for "does inference work from where Cortex runs analyzers".

Use cases:
  * CI / container build smoke test:
        docker run --rm --entrypoint python <image> AIMailAnalyzer/health.py
  * Operator probe from the default bridge network, the same place Cortex's
    per-job containers run:
        docker run --rm --entrypoint python <image> AIMailAnalyzer/health.py --require-server
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument(
        "--require-server",
        action="store_true",
        default=os.environ.get("INFERENCE_REQUIRE_SERVER", "").lower() in ("1", "true", "yes"),
        help="fail (exit 1) when the inference server is unreachable or not ready",
    )
    args = parser.parse_args(argv)

    try:
        import cortexutils.analyzer  # noqa: F401
        import requests  # noqa: F401

        from ai_mail_classifier import INFERENCE_SERVER_URL, build_session
    except Exception as exc:
        print(f"import_error: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    url = f"{INFERENCE_SERVER_URL.rstrip('/')}/health"
    try:
        resp = build_session().get(url, timeout=5)
        body = resp.json()
        if resp.ok:
            print(f"inference_server: ready at {url}, {body}")
        else:
            print(f"inference_server: reachable at {url} but NOT ready (HTTP {resp.status_code}), {body}",
                  file=sys.stderr)
            if args.require_server:
                return 1
    except Exception as exc:
        print(f"inference_server: unreachable at {url} ({exc})", file=sys.stderr)
        if args.require_server:
            return 1
        print("(informational only - pass --require-server to make this a failure)")

    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
