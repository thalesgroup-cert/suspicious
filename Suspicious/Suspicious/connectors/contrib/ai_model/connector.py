"""ai_model connector: the ``mail_ai`` analysis provider. Sends a case's mail text to the
AI inference server's /v2 API and returns its verdict, so the case is classified without
the Cortex AI analyzer. See docs/specs for the ai_model design."""
from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from ai_model import ledger
from ai_model.campaign_profile import COLLECTION_NAME
from ai_model.models import AiAssessment, LabelSyncState
from ai_model.taxonomy import FOLDERS, class_of
from case_handler.models import Case
from connectors.base import (
    EVENT_CASE_FINALISED,
    PROVIDER_KIND_MAIL_AI,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    ProviderResult,
    Schedule,
    valid_url,
)
from connectors.contrib.ai_model import imap_sync
from connectors.contrib.ai_model.campaigns import collection_mismatch
from connectors.contrib.ai_model.client import AiInferenceClient
from connectors.contrib.ai_model.mailtext import mail_archive_for, read_archive_body
from connectors.tasks import run_campaign_detection

logger = logging.getLogger("connectors.contrib.ai_model")

DEFAULT_URL = "http://ai_inference:8090"
DEFAULT_TIMEOUT = 20
FOLDER_BATCH = 500  # ruling D8: new mails per folder per run
EMBED_BATCH = 32  # the /v2/embed limit


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
            ConfigField("imap_host", "str",
                        help="IMAP server of the review mailbox. Empty: no label sync."),
            ConfigField("imap_port", "int", default=993),
            ConfigField("imap_user", "str"),
            ConfigField("imap_password", "secret"),
            ConfigField("imap_use_ssl", "bool", default=True),
            ConfigField("imap_folders", "str", default=",".join(FOLDERS),
                        help="Comma-separated review folders; the digit prefix gives the class."),
        ),
        events=(EVENT_CASE_FINALISED,),
        schedules=(Schedule("label-sync", 86400),),
        enabled_by_default=False,
        provides=PROVIDER_KIND_MAIL_AI,
    )

    def _client(self) -> AiInferenceClient:
        token = self.config.get("token")
        if not token:
            raise ValueError("token not configured")
        url = self.config.get("url") or DEFAULT_URL
        if not valid_url(url):
            raise ValueError("url is not a valid http(s) URL")
        return AiInferenceClient(
            url,
            token,
            float(self.config.get("timeout_seconds") or DEFAULT_TIMEOUT),
        )

    def health_check(self) -> HealthStatus:
        try:
            ok, detail = self._client().ready()
        except ValueError as exc:
            ok, detail = False, str(exc)
        # Campaign detection is a function of this connector too: say when the cleanup misses it.
        try:
            mismatch = collection_mismatch(COLLECTION_NAME)
        except Exception as exc:  # noqa: BLE001 — a health check must not raise
            logger.debug("Collection mismatch check failed: %s", type(exc).__name__)
            mismatch = None
        if mismatch:
            detail = f"{detail.rstrip('. ')}. {mismatch}" if detail else mismatch
        return HealthStatus(ok=ok, detail=detail)

    def on_case_finalised(self, event) -> None:
        # Only queued: this hook runs under the connector's breaker, which the classification
        # calls share, and a Chroma outage during detection must not open it.
        run_campaign_detection.delay(event.case_id)

    def analyze(self, kind: str, case_id: int) -> ProviderResult:
        case = Case.objects.select_related("fileOrMail__mail").get(pk=case_id)
        archive = mail_archive_for(case)
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

    def sync(self) -> None:
        """Nightly label sync: read the review folders (read-only) into the label ledger.

        Each folder's rows and its checkpoint commit together, only after its mails were embedded,
        so a failed embed leaves the checkpoint where it was and the next run retries. A folder
        that cannot be read is skipped; a failed login, a lost connection or an unavailable
        embed endpoint raises and fails the run (earlier folders stay committed).
        """
        host = self.config.get("imap_host")
        if not host:
            return
        client = self._client()
        imap = imap_sync.connect(
            host, int(self.config.get("imap_port") or 993), self.config.get("imap_user") or "",
            self.config.get("imap_password") or "", self.config.get("imap_use_ssl", True) is not False,
        )
        try:
            for folder in filter(None, (f.strip() for f in (self.config.get("imap_folders") or "").split(","))):
                if class_of(folder) is None:
                    logger.warning("ai_model sync: folder %s has no known class, skipped", ascii(folder)[:64])
                    continue
                try:
                    self._sync_folder(imap, client, folder)
                except imap_sync.FolderUnavailable as exc:
                    logger.warning("ai_model sync: folder unavailable: %s", exc)
        finally:
            try:
                imap.logout()
            except Exception:  # noqa: BLE001 -- the connection may already be gone
                pass

    def _sync_folder(self, imap, client, folder: str) -> None:
        state, _ = LabelSyncState.objects.get_or_create(folder=folder)
        mails, skipped, uidvalidity, last_uid = imap_sync.read_folder(
            imap, folder, since_uid=state.last_uid, limit=FOLDER_BATCH, known_uidvalidity=state.uidvalidity,
        )
        new = [m for m in mails if not ledger.is_observed(m)]
        answers = {"classifier": [], "campaign": []}
        versions = {}
        for start in range(0, len(new), EMBED_BATCH):
            texts = [m.text for m in new[start:start + EMBED_BATCH]]
            for profile, vectors in answers.items():
                answer = client.embed(texts, profile)
                if len(answer["vectors"]) != len(texts):
                    raise ValueError("embed answer does not match the batch size")
                vectors.extend(answer["vectors"])
                versions[profile] = answer
        with transaction.atomic():
            for i, mail in enumerate(new):
                ledger.record_folder_observation(
                    mail, {p: v[i] for p, v in answers.items()},
                    preprocessing_version=versions["classifier"]["preprocessing_version"],
                    embedding_version=versions["campaign"]["embedding_version"],
                )
            state.uidvalidity, state.last_uid, state.skipped = uidvalidity, last_uid, skipped
            state.last_run_at = timezone.now()
            state.save()
