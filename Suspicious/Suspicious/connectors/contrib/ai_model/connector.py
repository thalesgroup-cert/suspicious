"""ai_model connector: the ``mail_ai`` analysis provider. Sends a case's mail text to the
AI inference server's /v2 API and returns its verdict, so the case is classified without
the Cortex AI analyzer. See docs/specs for the ai_model design."""
from __future__ import annotations

import logging

from ai_model.models import AiAssessment
from case_handler.models import Case
from connectors.base import (
    PROVIDER_KIND_MAIL_AI,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    ProviderResult,
)
from connectors.contrib.ai_model.client import AiInferenceClient
from connectors.contrib.ai_model.mailtext import read_archive_body
from mail_feeder.models import MailArchive

logger = logging.getLogger("connectors.contrib.ai_model")

DEFAULT_URL = "http://ai_inference:8090"
DEFAULT_TIMEOUT = 20


def _inconclusive(reason: str) -> ProviderResult:
    return ProviderResult("INCONCLUSIVE", 0, 0, "No subclass found", "", {}, reason=reason)


def result_from_server(payload: dict) -> ProviderResult:
    """Map the /v2 classify answer to a ProviderResult. Score and confidence are rounded
    the way the Cortex AI parser did (score_process ai_mail), so verdicts stay comparable."""
    answer = payload["results"]["active"]
    sub_class = str(answer["sub_class"])
    return ProviderResult(
        result=answer["class"],
        score=round(float(answer["score"])),
        confidence=round(float(answer["confidence"]) * 100),
        category=sub_class.capitalize()[:Case._meta.get_field("category_ai").max_length],
        model_version=answer["version"],
        assessment={
            "sub_class": sub_class[:AiAssessment._meta.get_field("sub_class").max_length],
            "probabilities": answer["probabilities"],
            "sub_probabilities": answer["sub_probabilities"],
            "tier": answer.get("tier") or "",
            "contributing_phrases": answer["contributing_phrases"],
            "similar_cases": answer["similar_cases"],
            "campaign_embedding": payload["campaign_embedding"],
            "embedding_version": payload["campaign_embedding_version"],
            "latency_ms": payload["latency_ms"],
        },
    )


class AiModelConnector(Connector):
    manifest = ConnectorManifest(
        name="ai_model",
        version="1.0.0",
        author="Thales CERT",
        category="AI",
        description=(
            "Classifies a case's mail with the AI inference server instead of the Cortex AI "
            "analyzer, and keeps the full answer (probabilities, phrases, campaign embedding)."
        ),
        config_schema=(
            ConfigField("url", "url", required=True, default=DEFAULT_URL,
                        help="Base URL of the AI inference server."),
            ConfigField("token", "secret", required=True,
                        help="Bearer token the inference server expects (AI_INFERENCE_TOKEN)."),
            ConfigField("timeout_seconds", "int", default=DEFAULT_TIMEOUT),
        ),
        events=(),
        enabled_by_default=False,
        provides=PROVIDER_KIND_MAIL_AI,
    )

    def _client(self) -> AiInferenceClient:
        token = self.config.get("token")
        if not token:
            raise ValueError("token not configured")
        return AiInferenceClient(
            self.config.get("url") or DEFAULT_URL,
            token,
            float(self.config.get("timeout_seconds") or DEFAULT_TIMEOUT),
        )

    def health_check(self) -> HealthStatus:
        try:
            ok, detail = self._client().ready()
        except ValueError as exc:
            return HealthStatus(ok=False, detail=str(exc))
        return HealthStatus(ok=ok, detail=detail)

    def analyze(self, kind: str, case_id: int) -> ProviderResult:
        case = Case.objects.select_related("fileOrMail__mail").get(pk=case_id)
        mail = getattr(case.fileOrMail, "mail", None)
        archive = MailArchive.objects.select_related("archive", "mail").filter(mail=mail).first() if mail else None
        if archive is None:
            return _inconclusive("no_mail_archive")
        body = read_archive_body(archive)
        if body is None:
            return _inconclusive("archive_unreadable")
        client = self._client()
        try:
            payload = client.classify(body)
        except ValueError as exc:  # the server refused this mail: a verdict of "can't tell"
            logger.warning("ai_model: case %s refused by the inference server: %s", case_id, exc)
            return _inconclusive(str(exc))
        return result_from_server(payload)
