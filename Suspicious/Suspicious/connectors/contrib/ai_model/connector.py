"""ai_model connector: the ``mail_ai`` analysis provider. Sends a case's mail text to the
AI inference server's /v2 API and returns its verdict, so the case is classified without
the Cortex AI analyzer. See docs/specs for the ai_model design."""
from __future__ import annotations

import logging
from time import monotonic  # module-level so tests can patch the clock

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
FOLDER_BATCH = 500  # ruling D8: UIDs examined per folder per run (skipped and already-observed ones included)
CHUNK = 100  # mails embedded and committed together
TIME_BUDGET_SECONDS = 300  # a run stops between chunks and embed batches after this; Celery's soft limit is 540 s
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


class EmbedRefused(Exception):
    """The inference server refused a chunk's embed (4xx) or answered inconsistently: this folder only."""


class _BudgetSpent(Exception):
    pass


class LabelSyncIncomplete(Exception):
    """Raised after the run when some folders were skipped because their embed was refused. The
    other folders are committed; a retry would hit the same refusal, so it waits for the next run."""

    retryable = False


def _embed(client, texts: list[str], started: float) -> tuple[dict, dict]:
    """({profile: [vector, ...]}, versions) for both profiles, in batches of EMBED_BATCH.
    EmbedRefused on a 4xx, an answer that does not fit the batch or versions changing within it;
    _BudgetSpent when the time budget runs out before a later batch."""
    vectors = {"classifier": [], "campaign": []}
    seen = {"classifier": set(), "campaign": set()}
    for start in range(0, len(texts), EMBED_BATCH):
        if start and monotonic() - started >= TIME_BUDGET_SECONDS:
            raise _BudgetSpent
        batch = texts[start:start + EMBED_BATCH]
        for profile in vectors:
            try:
                answer = client.embed(batch, profile)
            except ValueError as exc:  # the message is not kept: only the class
                raise EmbedRefused(type(exc).__name__) from None
            if len(answer["vectors"]) != len(batch):
                raise EmbedRefused("answer does not match the batch size")
            vectors[profile].extend(answer["vectors"])
            seen[profile].add((answer["preprocessing_version"], answer["embedding_version"]))
    if any(len(v) > 1 for v in seen.values()):
        raise EmbedRefused("versions changed within a chunk")
    classifier, campaign = (next(iter(seen[p]), ("", "")) for p in ("classifier", "campaign"))
    return vectors, {"preprocessing_version": classifier[0], "embedding_version": campaign[1]}


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

        Each folder is read in chunks of CHUNK mails, up to FOLDER_BATCH per run. A chunk is
        embedded first, then its rows and the folder checkpoint commit in one transaction, so a
        failure leaves earlier chunks committed and the next run resumes after them. The run
        stops cleanly once TIME_BUDGET_SECONDS have passed (checked between chunks), under
        Celery's 540 s soft limit, also between embed batches (the cut chunk is not committed);
        a full backfill is the Task 7 command. A folder that cannot be read is skipped. A folder
        whose embed is refused (4xx, inconsistent answer) is skipped too, and once the other
        folders ran LabelSyncIncomplete (not retried) fails the delivery. A failed login, a lost
        connection or an unavailable embed endpoint raises at once and fails the run.
        """
        host = self.config.get("imap_host")
        if not host:
            return
        started = monotonic()
        client = self._client()
        folders = [f.strip() for f in (self.config.get("imap_folders") or "").split(",") if f.strip()]
        imap = imap_sync.connect(
            host, int(self.config.get("imap_port") or 993), self.config.get("imap_user") or "",
            self.config.get("imap_password") or "", self.config.get("imap_use_ssl", True) is not False,
        )
        refused = []
        try:
            for folder in folders or FOLDERS:
                if class_of(folder) is None:
                    logger.warning("ai_model sync: folder %s has no known class, skipped", ascii(folder)[:64])
                    continue
                try:
                    if not self._sync_folder(imap, client, folder, started):
                        logger.info("ai_model sync: time budget spent, stopping at %s", ascii(folder)[:64])
                        break
                except imap_sync.FolderUnavailable as exc:
                    logger.warning("ai_model sync: folder unavailable: %s", exc)
                except EmbedRefused as exc:
                    logger.warning("ai_model sync: embed refused for %s (%s), folder skipped", ascii(folder)[:64], exc)
                    refused.append(folder)
        finally:
            try:
                imap.logout()
            except Exception:  # noqa: BLE001 -- the connection may already be gone
                pass
        if refused:
            names = ", ".join(ascii(f)[:64] for f in refused)
            raise LabelSyncIncomplete(f"embed refused for {len(refused)} folder(s): {names}")

    def _sync_folder(self, imap, client, folder: str, started: float) -> bool:
        """Sync one folder chunk by chunk; False once the time budget is spent."""
        state, _ = LabelSyncState.objects.get_or_create(folder=folder)
        examined_total, skipped_total = 0, 0
        while examined_total < FOLDER_BATCH:
            if monotonic() - started >= TIME_BUDGET_SECONDS:
                return False
            mails, skipped, uidvalidity, last_uid = imap_sync.read_folder(
                imap, folder, since_uid=state.last_uid, limit=min(CHUNK, FOLDER_BATCH - examined_total),
                known_uidvalidity=state.uidvalidity,
            )
            examined = len(mails) + skipped
            examined_total, skipped_total = examined_total + examined, skipped_total + skipped
            new = [o for o in map(ledger.prepare_folder_observation, mails) if o is not None]
            try:
                vectors, versions = _embed(client, [o.mail.text for o in new], started)
            except _BudgetSpent:
                return False
            with transaction.atomic():
                state = LabelSyncState.objects.select_for_update().get(pk=state.pk)
                for i, observation in enumerate(new):
                    ledger.record_folder_observation(
                        observation, {p: v[i] for p, v in vectors.items()}, **versions,
                    )
                state.uidvalidity, state.last_uid, state.skipped = uidvalidity, last_uid, skipped_total
                state.last_run_at = timezone.now()
                state.save()
            if examined < CHUNK:
                break
        return True
