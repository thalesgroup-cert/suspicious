"""Token-protected /v2 API of the inference server."""
import json
import logging
import time
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from starlette.concurrency import run_in_threadpool

from training.recipe import PREPROCESSING_VERSION_TOKENS, NoNeighbours, chunk_mean_embedding

from . import bundles
from .auth import require_token
from .training_job import JOB_ID_RE, MAX_BODY, TrainRequest

logger = logging.getLogger("inference_server.v2")
# A classify body holds a whole mail (truncated to max_chars after parsing); JSON escapes can take
# 6 bytes per character, so the cap leaves room for that and still bounds what is read.
MAX_CLASSIFY_BODY = 32 * 2**20

# Version 0 (no bundle loaded): the legacy classifier as-is.
ACTIVE_VERSION = bundles.LEGACY_VERSION
# >= 0: -1 marks the case-less rows of a bundle's knn index, so it would exclude all of them
CaseId = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
NO_TOKENIZER = "token chunking is not available with this encoder"


def _can_chunk_by_tokens(vectorizer) -> bool:
    return hasattr(vectorizer, "tokenizer") and hasattr(vectorizer, "max_seq_length")


class ClassifyRequest(BaseModel):
    mail_body: str
    versions: list[str] = ["active"]
    # cases left out of the kNN vote (a ledger case is not its own neighbour); bundles only
    exclude_case_ids: list[CaseId] = Field(default_factory=list, max_length=1000)


async def _read_json(request: Request, model, cap=MAX_BODY, *, mail_text=False):
    """The body, capped while reading (Content-Length or not), validated by model. 422 answers
    carry `loc` and `msg` only, never input values: they may be presigned URLs or mail text.
    mail_text: parse with json.loads, which accepts a lone surrogate escape ("\\ud800") that
    pydantic's parser refuses; classify then replaces it, as before this reader existed."""
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > cap:
            raise HTTPException(413, "request body too large")
    try:
        if mail_text:
            try:
                data = json.loads(bytes(body))
            except (ValueError, RecursionError):  # RecursionError: deeply nested JSON
                raise HTTPException(422, [{"loc": [], "msg": "Invalid JSON"}]) from None
            return model.model_validate(data)
        return model.model_validate_json(bytes(body))
    except ValidationError as e:
        errors = e.errors(include_url=False, include_input=False, include_context=False)
        raise HTTPException(422, [{"loc": err["loc"], "msg": err["msg"]} for err in errors])


class EmbedRequest(BaseModel):
    texts: list[str] = Field(max_length=32)
    profile: Literal["classifier", "campaign"]
    # the classifier embedding's form; the campaign profile is always first-128 (cmp-e1)
    preprocessing: Literal[bundles.KNOWN_PREPROCESSING] = bundles.PREPROCESSING_LEGACY


def make_v2_router(*, store, classify, slots, max_chars, trainer, holder) -> APIRouter:
    """classify is server._classify(models, mail_body), which returns the legacy
    result dict; slots is the server's concurrency semaphore; trainer is the
    training_job.JobController (training runs in its own process, outside slots);
    holder is the bundles.ModelHolder (the loaded bundles, None = legacy weights)."""
    router = APIRouter(prefix="/v2")

    @router.post("/train", dependencies=[Depends(require_token)])
    async def train(request: Request):
        req = await _read_json(request, TrainRequest)
        # The first hash reads the encoder files (~1 GB): off the event loop.
        encoder_hash = await run_in_threadpool(trainer.encoder_hash)
        status, payload = trainer.start(req, encoder_hash=encoder_hash)
        return JSONResponse(payload, status_code=status)

    @router.post("/reload", dependencies=[Depends(require_token)])
    async def reload(request: Request):
        req = await _read_json(request, bundles.ReloadRequest)
        try:
            encoder_hash = await run_in_threadpool(store.encoder_hash)  # off the event loop
            versions = await run_in_threadpool(holder.reload, req, vectorizer=store.vectorizer,
                                               slots=slots, encoder_hash=encoder_hash)
        except bundles.ReloadBusy:
            raise HTTPException(409, "a reload is already running") from None
        except bundles.ReloadError as e:
            raise HTTPException(422, str(e)) from None
        except bundles.ReloadFailed:
            raise HTTPException(500, "reload failed") from None
        return versions  # {"active": {...}, "shadow": {...} (when loaded)}

    def _job(job_id, view):
        if not JOB_ID_RE.fullmatch(job_id) or view is None:
            raise HTTPException(404, "unknown job")
        return view

    @router.get("/train/{job_id}", dependencies=[Depends(require_token)])
    def train_state(job_id: str):
        return _job(job_id, trainer.get(job_id))

    @router.post("/train/{job_id}/cancel", dependencies=[Depends(require_token)])
    def train_cancel(job_id: str):
        return JSONResponse(_job(job_id, trainer.cancel(job_id)), status_code=202)

    @router.get("/health/live")
    def live():
        return {"live": True}

    @router.get("/health/ready")
    def ready():
        payload = store.health_payload()  # same body as the legacy /health
        return JSONResponse(payload, status_code=200 if payload["ready"] else 503)

    @router.get("/models/ai_mail", dependencies=[Depends(require_token)])
    def metadata():
        return {"name": "ai_mail", "versions": holder.describe()}

    @router.post("/models/ai_mail/classify", dependencies=[Depends(require_token)])
    async def classify_mail(request: Request):
        req = await _read_json(request, ClassifyRequest, MAX_CLASSIFY_BODY, mail_text=True)
        return await run_in_threadpool(_classify, req)

    def _classify(req: ClassifyRequest):
        # Only the active version exists until the registry lands.
        if req.versions != ["active"]:
            raise HTTPException(400, "Unsupported versions, expected ['active']")
        active, _ = holder.state  # read once: a concurrent reload does not change this request
        if active is None:
            detail = store.unavailable("personal")
        elif store.vectorizer is None:
            detail = f"Vectorizer unavailable: {store.vectorizer_error or 'still loading, try again shortly'}"
        else:
            detail = None
        if detail:
            raise HTTPException(503, detail)

        started = time.perf_counter()
        # A JSON "\ud800" escape gives a lone surrogate, which the tokenizer cannot encode: make it "?".
        body = req.mail_body[:max_chars].encode("utf-8", "replace").decode("utf-8")
        if active is None or active.preprocessing_version == bundles.PREPROCESSING_LEGACY:
            # version 0, or a legacy-first128 bundle: the legacy classify core, unchanged
            models = store.models("personal") if active is None else active.legacy_models()
            with slots:
                legacy = classify(models, body)
        else:
            if (active.preprocessing_version == PREPROCESSING_VERSION_TOKENS
                    and not _can_chunk_by_tokens(store.vectorizer)):
                raise HTTPException(422, NO_TOKENIZER)
            # one slot for the whole request: at most 8 chunk passes plus the campaign pass
            try:
                legacy = bundles.classify_bundle(active, store.vectorizer, body, slots,
                                                 exclude_case_ids=req.exclude_case_ids)
            except NoNeighbours as e:  # every neighbour excluded
                raise HTTPException(422, str(e)) from None
            except Exception as e:  # noqa: BLE001 - the class only: a message may hold mail data
                logger.error("bundle classify failed: %s", type(e).__name__)
                raise HTTPException(500, "classification failed") from None
        return {
            "results": {"active": {
                "version": active.version_id if active else ACTIVE_VERSION["id"],
                "class": legacy["classification"],
                "score": float(legacy["malscore"]),
                "confidence": float(legacy["confidence"]),
                "probabilities": legacy["classification_breakdown"],
                "sub_class": legacy["sub_classification"],
                "sub_class_confidence": float(legacy["sub_classification_confidence"]),
                "sub_probabilities": legacy["sub_classification_breakdown"],
                "contributing_phrases": legacy["contributing_phrases"],
                "tier": legacy.get("tier"),  # None: version 0 and legacy-first128, not calibrated
                "similar_cases": [],
            }},
            "campaign_embedding": legacy["email_embedding"],
            "campaign_embedding_version": ACTIVE_VERSION["campaign_embedding_version"],
            "latency_ms": round((time.perf_counter() - started) * 1000),
        }

    @router.post("/embed", dependencies=[Depends(require_token)])
    async def embed_route(request: Request):
        req = await _read_json(request, EmbedRequest, MAX_CLASSIFY_BODY, mail_text=True)
        return await run_in_threadpool(embed, req)

    def embed(req: EmbedRequest):
        # Version 0: both profiles use the legacy encode, so they give the same vectors.
        vectorizer = store.vectorizer
        if vectorizer is None:
            raise HTTPException(
                503, f"Vectorizer unavailable: {store.vectorizer_error or 'still loading, try again shortly'}"
            )
        texts = [t[:max_chars].encode("utf-8", "replace").decode("utf-8") for t in req.texts]
        pv = bundles.PREPROCESSING_LEGACY if req.profile == "campaign" else req.preprocessing
        by_tokens = pv == PREPROCESSING_VERSION_TOKENS
        if by_tokens and not _can_chunk_by_tokens(vectorizer):
            raise HTTPException(422, NO_TOKENIZER)
        if pv == bundles.PREPROCESSING_LEGACY:
            with slots:  # one batched pass, as before
                vectors = vectorizer.encode(texts, show_progress_bar=False)
        else:
            # a slot per text (up to 8 passes each), so a classify gets in between texts
            vectors = []
            for t in texts:
                with slots:
                    vectors.append(chunk_mean_embedding(vectorizer, t, by_tokens=by_tokens))
        return {
            "vectors": [[float(x) for x in row] for row in vectors],
            "preprocessing_version": pv,
            "embedding_version": ACTIVE_VERSION["campaign_embedding_version"],
        }

    return router
