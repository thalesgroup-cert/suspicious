"""Token-protected /v2 API, mounted beside the legacy /classify (untouched)."""
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from .auth import require_token

# The single version the server holds today: the legacy classifier as-is.
ACTIVE_VERSION = {
    "id": "v0",
    "preprocessing": "legacy-first128",
    "campaign_embedding_version": "cmp-e1",
    "calibrated": False,
}


def make_v2_router(*, store, classify, slots, max_chars) -> APIRouter:
    """classify, slots and max_chars are for the classify route added next;
    taking them here keeps server.py's wiring call stable."""
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

    return router
