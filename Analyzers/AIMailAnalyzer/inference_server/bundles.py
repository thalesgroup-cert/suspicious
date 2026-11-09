"""Bundle reload (POST /v2/reload) and bundle-aware classify (Plan E, Task 6b).

A reload names, per role (`active`, `shadow`), a version id, one presigned URL per bundle file
(training.bundle.BUNDLE_FILES plus manifest.json) and the manifest's SHA-256 pinned by Django
(Ruling E14). Every file is fetched with Task 6's downloader and URL rules (allow-list, no
redirects, no proxy, Content-Length required, raw body, the bundle's per-file and total caps
checked before anything is written) into a private 0700 directory under its fixed name, then read
once with read_bundle, the only bundle reader. The directory is removed on every exit path.
Then the server checks what read_bundle cannot know: the manifest's version id is the one asked
for, its preprocessing_version is one this server can apply, its input_dim is the loaded
encoder's width and, for token chunks, the encoder has a tokenizer. Any failure gives 422 and
leaves the current models untouched; both roles load before either is swapped in.

The loaded models live in one tuple (active, shadow), replaced under a lock: a classify reads
the tuple once and finishes on the objects it read. `active` None means the legacy v1 weights in
the operator-owned models/ directory (rollback to version 0). `shadow` is stored and reported but
not used by classify yet (Plan F)."""
import logging
import os
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Optional

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, field_validator

import mail_analysis
from mail_analysis import MODEL_SPECS
from training.bundle import JSON_CAPS, MAX_FILE, MAX_TOTAL, BundleError, read_bundle
from training.recipe import (
    HEADS, PREPROCESSING_VERSION_TOKENS, PREPROCESSING_VERSION_WORDS90, Heads, Knn,
    chunk_mean_embedding, predict,
)

from .training_job import (
    JOB_ID_PATTERN, MAX_URL, UPLOAD_NAMES, JobError, _env_int, allowed_hosts, check_url,
    default_base_dir, download, install_log_redaction, make_client, sweep,
)

logger = logging.getLogger("inference_server.bundles")
PREPROCESSING_LEGACY = "legacy-first128"
KNOWN_PREPROCESSING = (PREPROCESSING_LEGACY, PREPROCESSING_VERSION_TOKENS,
                       PREPROCESSING_VERSION_WORDS90)
CAMPAIGN_EMBEDDING_VERSION = "cmp-e1"
RELOAD_PREFIX = "ai-reload-"
# Version 0: the legacy classifier with the operator's models/ weights.
LEGACY_VERSION = {"id": "v0", "preprocessing": PREPROCESSING_LEGACY,
                  "campaign_embedding_version": CAMPAIGN_EMBEDDING_VERSION, "calibrated": False}
# training.recipe.HEADS and mail_analysis.MODEL_SPECS list the five heads in the same order.
LEGACY_FILE = dict(zip(HEADS, (spec.filename for spec in MODEL_SPECS)))


class ReloadError(Exception):
    """A 422 reason: names the role, file or rule, never a URL."""


class ReloadBusy(Exception):
    pass


class ReloadFailed(Exception):
    """An unexpected error while loading: a 500 with a generic body (logged by class name)."""


# --- request -----------------------------------------------------------------------------------

class BundleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version_id: str = Field(pattern=JOB_ID_PATTERN)
    bundle_urls: dict[str, str]
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("bundle_urls")
    @classmethod
    def _names(cls, v):
        if set(v) != set(UPLOAD_NAMES):
            raise ValueError("bundle_urls must name exactly the bundle files")
        if any(len(u) > MAX_URL for u in v.values()):
            raise ValueError("URL too long")
        return v


class ReloadRequest(BaseModel):
    """Both keys are required; null means legacy weights (active) or no shadow."""
    model_config = ConfigDict(extra="forbid", strict=True)
    active: Optional[BundleSpec]
    shadow: Optional[BundleSpec]


# --- the holder ----------------------------------------------------------------------------------

@dataclass(frozen=True)
class LoadedModel:
    version_id: str
    preprocessing_version: str
    manifest_sha256: str
    heads: Heads
    knn: Knn
    calibration: dict  # temperatures used by predict, tier_cutoffs used by tier_of

    def describe(self) -> dict:
        # calibrated: temperatures are applied on this path (not for legacy-first128 bundles)
        calibrated = self.preprocessing_version != PREPROCESSING_LEGACY
        return {"id": self.version_id, "preprocessing": self.preprocessing_version,
                "campaign_embedding_version": CAMPAIGN_EMBEDDING_VERSION, "calibrated": calibrated,
                "manifest_sha256": self.manifest_sha256}

    def legacy_models(self) -> dict:
        """The heads keyed as the legacy classify core expects (legacy-first128 bundles)."""
        return {LEGACY_FILE[h]: m for h, m in self.heads.models.items()}


def _encoder_width(vectorizer, slots) -> int:
    get = getattr(vectorizer, "get_sentence_embedding_dimension", None)
    width = get() if callable(get) else None
    if not width:
        with slots:
            width = len(vectorizer.encode(["width"], show_progress_bar=False)[0])
    return int(width)


class ModelHolder:
    def __init__(self, *, transport=None, tmp_base=None):
        self.transport = transport  # tests inject an httpx.MockTransport
        self.tmp_base = tmp_base
        self.state = (None, None)  # (active, shadow); read as one reference
        self._lock = threading.Lock()
        self._reload_lock = threading.Lock()

    def describe(self) -> dict:
        active, shadow = self.state
        out = {"active": active.describe() if active else dict(LEGACY_VERSION)}
        if shadow:
            out["shadow"] = shadow.describe()
        return out

    def reload(self, req: ReloadRequest, *, vectorizer, slots, encoder_hash=None) -> dict:
        if not self._reload_lock.acquire(blocking=False):
            raise ReloadBusy()
        try:
            install_log_redaction()
            base = self.tmp_base or default_base_dir()
            sweep(base, RELOAD_PREFIX)  # under the reload lock: no live reload directory exists
            specs = {role: getattr(req, role) for role in ("active", "shadow")}
            hosts = allowed_hosts()
            urls = {}
            for role, spec in specs.items():  # every URL is checked before any download
                if spec is not None:
                    try:
                        urls[role] = {n: check_url(spec.bundle_urls[n], hosts, f"{role} {n}")
                                      for n in UPLOAD_NAMES}
                    except JobError as e:
                        raise ReloadError(str(e)) from None
            width = None
            if urls:
                if vectorizer is None:
                    raise ReloadError("encoder not loaded")
                width = _encoder_width(vectorizer, slots)
            loaded = {role: None if spec is None else
                      self._load(role, spec, urls[role], base, vectorizer, width, encoder_hash)
                      for role, spec in specs.items()}
            with self._lock:
                self.state = (loaded["active"], loaded["shadow"])
            return self.describe()
        finally:
            self._reload_lock.release()

    def _load(self, role, spec, urls, base, vectorizer, width, encoder_hash=None) -> LoadedModel:
        deadline = time.monotonic() + _env_int("AI_RELOAD_MAX_SECONDS", 300, 1)

        def check():
            if time.monotonic() > deadline:
                raise JobError(f"{role}: time limit reached")

        workdir = tempfile.mkdtemp(prefix=RELOAD_PREFIX, dir=base)  # 0700
        try:
            os.mkdir(os.path.join(workdir, "heads"), 0o700)
            spent = 0
            with make_client(self.transport) as client:
                for name in UPLOAD_NAMES:
                    cap = min(MAX_FILE, JSON_CAPS.get(name, MAX_FILE), MAX_TOTAL - spent)
                    path = os.path.join(workdir, name)
                    download(client, urls[name], path, cap=cap, what=f"{role} {name}",
                             check=check)
                    spent += os.path.getsize(path)
            bundle = read_bundle(workdir, manifest_sha256=spec.manifest_sha256)
        except (JobError, BundleError) as e:
            raise ReloadError(f"{role}: {e}" if isinstance(e, BundleError) else str(e)) from None
        except Exception as e:  # noqa: BLE001 - the class only; the directory goes in finally
            logger.error("reload %s failed: %s", role, type(e).__name__)
            raise ReloadFailed() from None
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        manifest = bundle.manifest
        if manifest["version_id"] != spec.version_id:
            raise ReloadError(f"{role}: the manifest's version_id is not the requested version")
        pv = manifest["preprocessing_version"]
        if pv not in KNOWN_PREPROCESSING:
            raise ReloadError(f"{role}: unknown preprocessing_version")
        # A manifest that names an encoder must name this one; a server without a hash refuses
        # it. A manifest with an empty encoder_hash is not checked.
        if manifest["encoder_hash"] and manifest["encoder_hash"] != encoder_hash:
            raise ReloadError(f"{role}: the bundle was trained with another encoder")
        if bundle.input_dim != width:
            raise ReloadError(f"{role}: input_dim {bundle.input_dim} differs from the encoder "
                              f"width {width}")
        if pv == PREPROCESSING_VERSION_TOKENS and not (
                hasattr(vectorizer, "tokenizer") and hasattr(vectorizer, "max_seq_length")):
            raise ReloadError(f"{role}: token chunking needs the encoder tokenizer")
        return LoadedModel(spec.version_id, pv, spec.manifest_sha256, bundle.heads, bundle.knn,
                           bundle.calibration)


# --- classify ----------------------------------------------------------------------------------

def tier_of(p: float, cutoffs: dict) -> str:
    """The confidence tier of a calibrated probability: High at or above cutoffs["high"], Medium
    at or above cutoffs["medium"], else Low (spec section 9)."""
    return "high" if p >= cutoffs["high"] else "medium" if p >= cutoffs["medium"] else "low"


def classify_bundle(model: LoadedModel, vectorizer, body: str, slots,
                    exclude_case_ids=None) -> dict:
    """A chunk-mean bundle's answer, in the legacy classify core's dict shape. The heads see the
    chunk-mean embedding in the bundle's form; the campaign embedding stays the plain first-128
    pass (cmp-e1). Main probabilities are training.recipe.predict's calibrated blend; sub-type
    probabilities are weighted by the main probability as the legacy path does. Class, score and
    confidence come from the calibrated probabilities through the legacy mapping (a class only
    at 0.5 or above), and `tier` from the top one and the bundle's tier_cutoffs. Contributing
    phrases are not computed (an occlusion pass would cost up to 40 chunked re-embeddings).
    Raises training.recipe.NoNeighbours when exclude_case_ids leaves no neighbour."""
    by_tokens = model.preprocessing_version == PREPROCESSING_VERSION_TOKENS
    with slots:
        x = chunk_mean_embedding(vectorizer, body, by_tokens=by_tokens)
        campaign = vectorizer.encode([body], show_progress_bar=False)
        p = predict(model.heads, model.knn, x[None], temperature=model.calibration["temperature"],
                    exclude_case_ids=exclude_case_ids)
    main = p.main[0]
    sub = np.concatenate([p.sub["safe"][0] * main[0], p.sub["unwanted"][0] * main[1],
                          p.sub["dangerous"][0] * main[2]])
    info = mail_analysis.getMainClassificationInfo(main)
    sub_info = mail_analysis.getSubClassificationInfo(sub)
    return {
        "malscore": str(info["score"]),
        "classification": info["classification"],
        "confidence": str(info["confidence"]),
        "classification_breakdown": mail_analysis.get_classification_breakdown(main),
        "sub_classification": sub_info["classification"],
        "sub_classification_confidence": str(sub_info["confidence"]),
        "sub_classification_breakdown": mail_analysis.get_sub_classification_breakdown(sub),
        "contributing_phrases": [],
        "email_embedding": str(campaign.tolist()[0]),
        "tier": tier_of(float(main.max()), model.calibration["tier_cutoffs"]),
    }
