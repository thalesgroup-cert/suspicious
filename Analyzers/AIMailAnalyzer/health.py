#!/usr/bin/env python3
"""
Standalone model-load probe for AIMailAnalyzer (P7).

This image runs as a Cortex one-shot analyzer (ENTRYPOINT
ai_mail_classifier.py), so there is no long-running HTTP service to
expose a /health endpoint on. The architectural recommendation in the
2026-04-15 review (persistent HTTP service + /health) does not match
the current Cortex contract, and a refactor would break that contract.

What this script does instead:
  * Loads the paraphrase-multilingual-mpnet-base-v2 vectoriser
  * Loads both ResNetMLP weight files
  * Prints "ok" and exits 0 on full success
  * Prints the failure reason and exits 1 on any error

Use cases:
  * CI / container build smoke test:
        docker run --rm --entrypoint python <image> AIMailAnalyzer/health.py
  * Operator probe after pushing a new image
  * Foundation for a future HTTP wrapper if the analyzer is ever
    promoted to a long-running service
"""

from __future__ import annotations

import os
import sys
import traceback


from mail_analysis import MODEL_SPECS

VECTORIZER_PATH = (
    "/worker/AIMailAnalyzer/vectorizers/paraphrase-multilingual-mpnet-base-v2"
)
MODEL_DIR = "/worker/AIMailAnalyzer/models"


def main() -> int:
    try:
        import torch
        from sentence_transformers import SentenceTransformer

        from ResNetMLP import ResNetMLP
    except Exception as exc:
        print(f"import_error: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    try:
        SentenceTransformer(VECTORIZER_PATH)
    except Exception as exc:
        print(f"vectorizer_load_error: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    try:
        device = torch.device("cpu")
        for spec in MODEL_SPECS:
            path = os.path.join(MODEL_DIR, spec.filename)
            model = ResNetMLP(768, spec.output_dim).to(device)
            model.load_state_dict(torch.load(path, weights_only=True))
    except Exception as exc:
        print(f"model_load_error: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
