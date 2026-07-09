"""Bespoke parser for AI_Mail_Analyzer (classification/malscore/confidence shape).

Score extraction is pure; the campaign/ChromaDB/TheHive side-effects are ported
unchanged from the former AnalyzerAI and run in _run_campaign() (best-effort).
"""
from __future__ import annotations

import logging
from functools import cached_property
from typing import Any, Dict, List

from minio import Minio
from common.clients import get_chroma_client, get_s3_client

from case_handler.models import Case
from ..base import AnalyzerParser, AnalyzerManifest
from ..result import AnalyzerResult
from .ai_minio_utils import build_mail_zip_from_minio, fetch_mail_files_from_minio
from connectors.contrib.thehive.attachments import add_binary_attachment_to_item
from connectors.contrib.thehive.utils import (
    parse_and_decode_defaultdict,
    get_phishing_campaign,
    get_most_common_subject,
    get_most_common_alert_id,
    extract_sender_domain_from_headers,
    is_domain_in_campaign_allow_list,
)
from score_process.score_utils.chromadb_utils import (
    get_suspicious_collection,
    get_similar_dangerous_mails,
    add_to_suspicious_collection,
    update_suspicious_collection,
)
from connectors.contrib.thehive.phishing import (
    PHISHING_CAMPAIGN_TEMPLATE,
    create_new_alert,
    get_item_from_id,
    add_observables_to_item,
    build_mail_observables_from_headers,
    build_mail_observables_from_html,
)

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

DANGEROUS_MALSCORE_THRESHOLD = 6.5


class AiMailParser(AnalyzerParser):
    manifest = AnalyzerManifest(
        name="ai_mail",
        cortex_names=("AI_Mail_Analyzer", "AI_Mail_Analyzer_2_0"),
        data_types=("file",),
    )

    def parse(self, summary: Any, full: Any) -> AnalyzerResult:
        self.summary, self.full = summary, full          # helpers read these
        score, confidence, level, details = 5, 0, "info", {}

        if isinstance(summary, dict):
            try:
                score = round(float(summary.get("malscore", 5)))
                confidence = round(float(summary.get("confidence", 0)) * 100)  # 0-1 → 0-100
                level = str(summary.get("classification", "info")).lower()
            except (TypeError, ValueError) as exc:
                logger.warning("[ai_mail] score parse failed: %s", exc)

        if isinstance(full, dict):
            for key in ("classification_probabilities", "report",
                        "malscore", "confidence", "classification"):
                if key in full:
                    details[key] = full[key]

        result = AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, category=[level],
            level=level, details=details,
        )
        self._run_campaign(result)   # best-effort side-effects, never raises
        return result

    def _run_campaign(self, result: AnalyzerResult) -> None:
        """Ported verbatim from AnalyzerAI.process campaign branch. Best-effort."""
        try:
            if not self.full:
                return

            malscore = self._get_malscore(result)
            collection = self._chroma_collection

            if malscore <= DANGEROUS_MALSCORE_THRESHOLD:
                logger.info("Mail (case=%s) not dangerous (malscore=%.2f).", self.case_id, malscore)
                self._add_to_chroma(collection, alert_id="", source_ref="")
                return

            logger.info("Mail (case=%s) considered dangerous (malscore=%.2f).", self.case_id, malscore)

            self._decode_headers()

            sender_domain = extract_sender_domain_from_headers(
                self.full["report"].get("analyzed_mail_headers", {})
            )
            if sender_domain and is_domain_in_campaign_allow_list(sender_domain):
                logger.info("Sender domain %r is allow-listed — skipping campaign detection.", sender_domain)
                return

            self._handle_campaign(result, collection)

        except Exception as exc:
            logger.error("[ai_mail] campaign side-effect error (case=%s): %s",
                         self.case_id, exc, exc_info=True)

    # ── lazy config access ────────────────────────────────────────────────

    @cached_property
    def _thehive(self) -> Dict[str, str]:
        from settings.config import get_section
        cfg = get_section("integrations.thehive")
        return {
            "url": cfg.get("url", ""),
            "key": cfg.get("api_key", ""),
            "verify": cfg.get("certificate_path") or True,
        }

    # ── ChromaDB singleton — one client per parser instance ───────────────

    @cached_property
    def _chroma_collection(self):
        try:
            client = get_chroma_client()
            return get_suspicious_collection(client)
        except Exception as exc:
            logger.error("ChromaDB init failed: %s", exc)
            return None

    def _make_minio_client(self) -> Minio:
        return get_s3_client()

    # ── private helpers (ported unchanged from AnalyzerAI) ────────────────

    def _get_malscore(self, result: AnalyzerResult) -> float:
        try:
            return float(result.details.get("malscore", result.score))
        except (TypeError, ValueError):
            return 5.0

    def _decode_headers(self) -> None:
        try:
            raw = self.full.get("report", {}).get("analyzed_mail_headers", "")
            self.full["report"]["analyzed_mail_headers"] = parse_and_decode_defaultdict(str(raw))
        except Exception as exc:
            logger.error("Header decode error (case=%s): %s", self.case_id, exc)

    def _add_to_chroma(self, collection, *, alert_id: str, source_ref: str) -> None:
        if collection is None:
            return
        try:
            add_to_suspicious_collection(
                self.full, alert_id, source_ref, self.case_id, collection,
            )
        except Exception as exc:
            logger.error("add_to_suspicious_collection error (case=%s): %s", self.case_id, exc)

    def _handle_campaign(self, result: AnalyzerResult, collection) -> None:
        hive_url = self._thehive["url"]
        hive_key = self._thehive["key"]
        hive_verify = self._thehive["verify"]

        embedding = result.details["report"].get("email_embedding")
        similar   = get_similar_dangerous_mails(embedding, collection, n_results=20) if embedding else {}
        campaign  = get_phishing_campaign(similar)

        if not campaign:
            logger.info("No campaign detected for case %s.", self.case_id)
            self._add_to_chroma(collection, alert_id="", source_ref="")
            return

        logger.info("Campaign detected for case %s.", self.case_id)

        alert_id, item_type, item = self._get_or_create_alert(campaign, hive_url, hive_key)

        if item_type == "new":
            update_suspicious_collection(
                campaign, alert_id, item.get("sourceRef", ""), collection
            )
            item_type = "alert"

        # Collect all case IDs in the campaign plus the current one.
        # metadatas is a list-of-lists from ChromaDB — flatten it to get
        # individual metadata dicts.
        meta_dicts: List[Dict] = [
            m for sublist in (similar.get("metadatas") or []) for m in sublist
        ]
        campaign_case_ids: List[int] = []
        for m in meta_dicts:
            try:
                campaign_case_ids.append(int(m["suspicious_case_id"]))
            except (KeyError, TypeError, ValueError):
                pass
        all_case_ids = list(dict.fromkeys(campaign_case_ids + [self.case_id]))

        # Create Minio client ONCE before the loop
        minio_client = self._make_minio_client()

        for case_id in all_case_ids:
            self._attach_case_to_alert(
                case_id, alert_id, item_type, minio_client, hive_url, hive_key, hive_verify
            )

        self._add_to_chroma(collection, alert_id=alert_id, source_ref=item.get("sourceRef", ""))

    def _get_or_create_alert(self, campaign, hive_url: str, hive_key: str):
        """Return (alert_id, item_type, item_dict).

        item_type is "alert" for an existing item, "new" for a freshly
        created alert (so the caller knows to call update_suspicious_collection).
        """
        try:
            alert_id = get_most_common_alert_id(campaign)
        except Exception:
            alert_id = ""

        if alert_id:
            item_type, item = get_item_from_id(alert_id, hive_url, hive_key)
            return alert_id, item_type, item

        item = create_new_alert(
            None,
            PHISHING_CAMPAIGN_TEMPLATE["title"](get_most_common_subject(campaign)),
            PHISHING_CAMPAIGN_TEMPLATE["description"](
                self.full.get("classification", ""),
                self.full.get("sub_classification", ""),
                self.full.get("report", {}).get("analyzed_mail_content", ""),
            ),
            PHISHING_CAMPAIGN_TEMPLATE["severity"],
            PHISHING_CAMPAIGN_TEMPLATE["tlp"],
            PHISHING_CAMPAIGN_TEMPLATE["pap"],
            "Suspicious",
            hive_url,
            hive_key,
            PHISHING_CAMPAIGN_TEMPLATE["tags"],
        )
        alert_id = item["_id"]
        return alert_id, "new", item

    def _attach_case_to_alert(
        self,
        case_id: int,
        alert_id: str,
        item_type: str,
        minio_client: Minio,
        hive_url: str,
        hive_key: str,
        verify: str | bool = True,
    ) -> None:
        try:
            case     = Case.objects.get(id=case_id)
            mail_id  = str(case.fileOrMail.mail.mail_id)
            reporter = case.reporter.username

            zip_name, zip_bytes = build_mail_zip_from_minio(minio_client, mail_id, reporter)
            headers, _eml, _txt, html = fetch_mail_files_from_minio(minio_client, mail_id)

            if zip_bytes:
                add_binary_attachment_to_item(
                    item_type, alert_id, zip_name, zip_bytes, hive_url, hive_key, verify
                )
            if headers:
                add_observables_to_item(
                    item_type, alert_id,
                    build_mail_observables_from_headers(headers),
                    hive_url, hive_key,
                )
            if html:
                add_observables_to_item(
                    item_type, alert_id,
                    build_mail_observables_from_html(html),
                    hive_url, hive_key,
                )

        except Case.DoesNotExist:
            logger.warning("Case %s not found — skipping attachment.", case_id)
        except Exception as exc:
            logger.error(
                "Attachment/observable error for case %s (alert %s): %s",
                case_id, alert_id, exc, exc_info=True,
            )
