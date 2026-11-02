#!/usr/bin/env python3
"""Persistent inference server for AIMailAnalyzer.

Loads the vectorizer and every model variant ONCE at startup and keeps them
resident in memory (a full SentenceTransformer + 5 ResNetMLP checkpoints). The
ai_model connector POSTs each mail body to the token-protected /v2 API (v2.py)
over suspicious_net, as http://ai_inference:8090.

One variant is loaded: "personal" (models/, trained on this deployment's own
labeled mail), the one /v2 classifies with.

Weights stay fresh: the monthly retrain pipeline overwrites models/*.pth in
place, so each variant's files are re-checked (mtime) every
INFERENCE_RELOAD_CHECK_SECONDS and hot-swapped when they change. POST /reload
forces the same check immediately. A file that fails to load (half-copied,
corrupt) never replaces a working model.
"""
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from typing import NamedTuple, Optional

import numpy as np
import torch
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sentence_transformers import SentenceTransformer

import mail_analysis
from mail_analysis import MODEL_SPECS
from ResNetMLP import ResNetMLP

from .training_job import JobController
from .v2 import make_v2_router

logger = logging.getLogger("inference_server")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

VECTORIZER_PATH = os.environ.get(
    "VECTORIZER_PATH",
    "/worker/AIMailAnalyzer/vectorizers/paraphrase-multilingual-mpnet-base-v2",
)
MODEL_DIRS = {
    "personal": os.environ.get("MODELS_DIR_PERSONAL", "/worker/AIMailAnalyzer/models"),
}

# Seconds between on-disk weight checks (0 disables the automatic check; POST
# /reload still works).
RELOAD_CHECK_SECONDS = float(os.environ.get("INFERENCE_RELOAD_CHECK_SECONDS", "30"))
# Concurrent classifications. Each one is CPU-bound torch work (plus up to ~40
# extra encodes for the contributing-phrases pass), so letting FastAPI's whole
# threadpool run them at once only thrashes the cores.
MAX_CONCURRENCY = max(1, int(os.environ.get("INFERENCE_MAX_CONCURRENCY", "2")))
# The vectorizer only reads the first max_seq_length tokens of a body anyway;
# this just bounds tokenisation cost for a pathological multi-megabyte mail.
MAX_MAIL_CHARS = int(os.environ.get("INFERENCE_MAX_MAIL_CHARS", "200000"))

# The unwanted (spam/newsletter) sub-model is trained last and only once enough
# labeled samples exist (see the retrain pipeline's per-model resilience), so a
# variant without it is still usable - mail_analysis zero-fills its slice.
OPTIONAL_MODELS = frozenset({"unwanted_30_epochs_model.pth"})
REQUIRED_MODELS = tuple(
    spec.filename for spec in MODEL_SPECS if spec.filename not in OPTIONAL_MODELS
)

device = torch.device("cpu")


class Slot(NamedTuple):
    """One .pth file's state: the live model (None = never loaded), the mtime it
    was loaded from, and the last load error (cleared on success)."""
    model: Optional[torch.nn.Module]
    mtime_ns: Optional[int]
    error: Optional[str]


def _load_model(path: str, output_dim: int) -> torch.nn.Module:
    model = ResNetMLP(768, output_dim).to(device)
    model.load_state_dict(torch.load(path, map_location=device, weights_only=True))
    model.eval()
    return model


class ModelStore:
    """Vectorizer + per-variant model slots, with thread-safe hot reload."""

    def __init__(self, model_dirs: dict):
        self.model_dirs = model_dirs
        self.vectorizer: Optional[SentenceTransformer] = None
        self.vectorizer_error: Optional[str] = None
        self.slots = {
            variant: {spec.filename: Slot(None, None, None) for spec in MODEL_SPECS}
            for variant in model_dirs
        }
        self._lock = threading.Lock()
        self._last_check = time.monotonic()

    # -- loading ----------------------------------------------------------

    def load_vectorizer(self, path: str) -> None:
        try:
            self.vectorizer = SentenceTransformer(path, device=str(device))
            self.vectorizer_error = None
        except Exception as exc:  # noqa: BLE001 - surfaced via /health, not swallowed
            self.vectorizer = None
            self.vectorizer_error = f"{type(exc).__name__}: {exc}"
            logger.error("could not load vectorizer from %s: %s", path, exc)

    def refresh(self, force: bool = False) -> dict:
        """(Re)load every model file that is new or changed on disk.

        Returns {variant: [filenames reloaded]}. A load failure keeps the
        previous model (if any) and records the error; the file is retried on
        the next check because its mtime is only committed on success.
        """
        reloaded = {}
        with self._lock:
            for variant, model_dir in self.model_dirs.items():
                reloaded[variant] = []
                for spec in MODEL_SPECS:
                    old = self.slots[variant][spec.filename]
                    path = os.path.join(model_dir, spec.filename)
                    try:
                        mtime_ns = os.stat(path).st_mtime_ns
                    except OSError as exc:
                        # Missing file: keep whatever is already serving (a
                        # promote may be mid-swap), just remember why.
                        self.slots[variant][spec.filename] = old._replace(error=f"{type(exc).__name__}: {exc}")
                        continue
                    if not force and old.model is not None and old.mtime_ns == mtime_ns:
                        continue
                    try:
                        model = _load_model(path, spec.output_dim)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("variant=%s: could not load %s: %s", variant, spec.filename, exc)
                        self.slots[variant][spec.filename] = old._replace(error=f"{type(exc).__name__}: {exc}")
                        continue
                    self.slots[variant][spec.filename] = Slot(model, mtime_ns, None)
                    reloaded[variant].append(spec.filename)
                    logger.info("variant=%s: loaded %s", variant, spec.filename)
            self._last_check = time.monotonic()
        return reloaded

    def maybe_refresh(self) -> None:
        if RELOAD_CHECK_SECONDS <= 0:
            return
        if time.monotonic() - self._last_check < RELOAD_CHECK_SECONDS:
            return
        # Only one request pays for the stat() sweep; the rest keep serving.
        if self._lock.locked():
            return
        self.refresh()

    # -- reading ----------------------------------------------------------

    def models(self, variant: str) -> dict:
        """Snapshot {filename: model-or-None}; safe against a concurrent swap."""
        return {name: slot.model for name, slot in self.slots[variant].items()}

    def missing_required(self, variant: str) -> list:
        models = self.models(variant)
        return [name for name in REQUIRED_MODELS if models.get(name) is None]

    def variant_ready(self, variant: str) -> bool:
        return not self.missing_required(variant)

    def unavailable(self, variant: str) -> Optional[str]:
        """The 503 detail for a classify call that cannot be served, else None.
        Used by the /v2 classify route."""
        if self.vectorizer is None:
            return f"Vectorizer unavailable: {self.vectorizer_error or 'still loading, try again shortly'}"
        self.maybe_refresh()
        missing = self.missing_required(variant)
        if missing:
            return (
                f"Required models unavailable for variant {variant!r}: {', '.join(missing)} "
                f"(looked in {self.model_dirs[variant]})"
            )
        return None

    def ready(self) -> bool:
        """Serving requires the vectorizer and the "personal" variant."""
        return self.vectorizer is not None and self.variant_ready("personal")

    def health_payload(self) -> dict:
        return {
            "ready": self.ready(),
            "vectorizer": {"loaded": self.vectorizer is not None, "error": self.vectorizer_error},
            "variants": {
                variant: {
                    "ready": self.variant_ready(variant),
                    "models": {
                        name: {"loaded": slot.model is not None, "error": slot.error}
                        for name, slot in slots.items()
                    },
                }
                for variant, slots in self.slots.items()
            },
        }


store = ModelStore(MODEL_DIRS)
_inference_slots = threading.BoundedSemaphore(MAX_CONCURRENCY)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info("Loading vectorizer from %s ...", VECTORIZER_PATH)
    store.load_vectorizer(VECTORIZER_PATH)
    for variant, model_dir in MODEL_DIRS.items():
        logger.info("Loading '%s' models from %s ...", variant, model_dir)
    store.refresh(force=True)
    logger.info("Startup finished, ready=%s", store.ready())
    yield


app = FastAPI(title="AIMailAnalyzer inference server", lifespan=lifespan)


def _health_payload() -> dict:
    return store.health_payload()


@app.get("/health")
def health():
    # 503 until the vectorizer and the "personal" variant are usable, so a
    # container healthcheck / load balancer sees "not ready" instead of a
    # server that answers 200 and then 503s every classify call.
    payload = _health_payload()
    return JSONResponse(payload, status_code=200 if payload["ready"] else 503)


@app.post("/reload")
def reload_models():
    """Re-read weights from disk now (e.g. right after the retrain pipeline
    promotes new ones) instead of waiting for the periodic check."""
    reloaded = store.refresh(force=True)
    return {"reloaded": reloaded, **_health_payload()}


def _classify(models: dict, mail_body: str) -> dict:
    vectorizer = store.vectorizer

    safe_suspicious_model = models["safe_suspicious_30_epochs_model.pth"]
    spam_dangerous_model = models["spam_dangerous_30_epochs_model.pth"]
    safe_model = models["safe_30_epochs_model.pth"]
    spam_model = models.get("unwanted_30_epochs_model.pth")  # optional, see OPTIONAL_MODELS
    dangerous_model = models["dangerous_30_epochs_model.pth"]

    email_embedding = vectorizer.encode([mail_body], show_progress_bar=False)

    classification_probabilities = mail_analysis.getMainClassificationProbabilities(
        device, safe_suspicious_model, spam_dangerous_model, email_embedding
    )
    classification_info = mail_analysis.getMainClassificationInfo(classification_probabilities)

    sub_classification_probabilities = mail_analysis.getSubClassificationProbabilities(
        device, [safe_model, spam_model, dangerous_model], email_embedding, classification_probabilities
    )
    sub_classification_info = mail_analysis.getSubClassificationInfo(sub_classification_probabilities)

    classification_breakdown = mail_analysis.get_classification_breakdown(classification_probabilities)
    sub_classification_breakdown = mail_analysis.get_sub_classification_breakdown(sub_classification_probabilities)

    contributing_phrases = mail_analysis.get_contributing_phrases(
        device, safe_suspicious_model, spam_dangerous_model, vectorizer,
        mail_body,
        classification_index=int(np.argmax(classification_probabilities)),
        baseline_probability=float(np.max(classification_probabilities)),
    )

    return {
        "malscore": str(classification_info["score"]),
        "classification": classification_info["classification"],
        "confidence": str(classification_info["confidence"]),
        "classification_probabilities": str(classification_probabilities),
        "classification_breakdown": classification_breakdown,
        "sub_classification": sub_classification_info["classification"],
        "sub_classification_confidence": str(sub_classification_info["confidence"]),
        "sub_classification_probabilities": str(sub_classification_probabilities),
        "sub_classification_breakdown": sub_classification_breakdown,
        "contributing_phrases": contributing_phrases,
        # str(list): v2 returns it as campaign_embedding, which the campaign
        # detector json.loads.
        "email_embedding": str(email_embedding.tolist()[0]),
    }


# Token-protected /v2 API; needs _classify, so it is mounted here rather than
# right after app = FastAPI(...).
trainer = JobController()
app.include_router(
    make_v2_router(store=store, classify=_classify, slots=_inference_slots, max_chars=MAX_MAIL_CHARS,
                   trainer=trainer)
)

