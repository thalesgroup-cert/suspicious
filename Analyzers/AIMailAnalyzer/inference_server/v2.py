"""Token-protected /v2 API of the inference server."""
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .auth import require_token

# The single version the server holds today: the legacy classifier as-is.
ACTIVE_VERSION = {
    "id": "v0",
    "preprocessing": "legacy-first128",
    "campaign_embedding_version": "cmp-e1",
    "calibrated": False,
}


class ClassifyRequest(BaseModel):
    mail_body: str
    versions: list[str] = ["active"]


class EmbedRequest(BaseModel):
    texts: list[str] = Field(max_length=32)
    profile: Literal["classifier", "campaign"]


def make_v2_router(*, store, classify, slots, max_chars) -> APIRouter:
    """classify is server._classify(models, mail_body), which returns the legacy
    result dict; slots is the server's concurrency semaphore."""
    router = APIRouter(prefix="/v2")

    @router.get("/health/live")
    def live():
        return {"live": True}

    @router.get("/health/ready")
    def ready():
        payload = store.health_payload()  # same body as the legacy /health
        return JSONResponse(payload, status_code=200 if payload["ready"] else 503)

    @router.get("/models/ai_mail", dependencies=[Depends(require_token)])
    def metadata():
        return {"name": "ai_mail", "versions": {"active": ACTIVE_VERSION}}

    @router.post("/models/ai_mail/classify", dependencies=[Depends(require_token)])
    def classify_mail(req: ClassifyRequest):
        # Only the active version exists until the registry lands.
        if req.versions != ["active"]:
            raise HTTPException(400, f"Unsupported versions {req.versions!r}, expected ['active']")
        detail = store.unavailable("personal")
        if detail:
            raise HTTPException(503, detail)

        models = store.models("personal")
        started = time.perf_counter()
        # A JSON "\ud800" escape gives a lone surrogate, which the tokenizer cannot encode: make it "?".
        body = req.mail_body[:max_chars].encode("utf-8", "replace").decode("utf-8")
        with slots:
            legacy = classify(models, body)
        return {
            "results": {"active": {
                "version": ACTIVE_VERSION["id"],
                "class": legacy["classification"],
                "score": float(legacy["malscore"]),
                "confidence": float(legacy["confidence"]),
                "probabilities": legacy["classification_breakdown"],
                "sub_class": legacy["sub_classification"],
                "sub_class_confidence": float(legacy["sub_classification_confidence"]),
                "sub_probabilities": legacy["sub_classification_breakdown"],
                "contributing_phrases": legacy["contributing_phrases"],
                "tier": None,
                "similar_cases": [],
            }},
            "campaign_embedding": legacy["email_embedding"],
            "campaign_embedding_version": ACTIVE_VERSION["campaign_embedding_version"],
            "latency_ms": round((time.perf_counter() - started) * 1000),
        }

    @router.post("/embed", dependencies=[Depends(require_token)])
    def embed(req: EmbedRequest):
        # Version 0: both profiles use the legacy encode, so they give the same vectors.
        vectorizer = store.vectorizer
        if vectorizer is None:
            raise HTTPException(
                503, f"Vectorizer unavailable: {store.vectorizer_error or 'still loading, try again shortly'}"
            )
        texts = [t[:max_chars].encode("utf-8", "replace").decode("utf-8") for t in req.texts]
        with slots:
            vectors = vectorizer.encode(texts, show_progress_bar=False)
        return {
            "vectors": [[float(x) for x in row] for row in vectors],
            "preprocessing_version": ACTIVE_VERSION["preprocessing"],
            "embedding_version": ACTIVE_VERSION["campaign_embedding_version"],
        }

    return router
