# analyzers_services/ai/service.py
"""
AI mail analyzer — scores a mail with the AI model and creates/updates
a TheHive campaign alert when the mail is considered dangerous.
"""
from __future__ import annotations

import json
import logging
from functools import cached_property
from typing import Any, Dict, List, Optional

import chromadb
from minio import Minio

from case_handler.models import Case
from ..base import BaseAnalyzer
from .minio_utils import build_mail_zip_from_minio, fetch_mail_files_from_minio
from .thehive_utils import add_binary_attachment_to_item

from score_process.score_utils.thehive.utils import (
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
from score_process.score_utils.thehive.phishing import (
    PHISHING_CAMPAIGN_TEMPLATE,
    create_new_alert,
    get_item_from_id,
    add_observables_to_item,
    build_mail_observables_from_headers,
    build_mail_observables_from_html,
)

CONFIG_PATH = "/app/settings.json"
DANGEROUS_MALSCORE_THRESHOLD = 6.5

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


def _load_config() -> Dict[str, Any]:
    """Load settings.json lazily — raises at call time, not at import time."""
    with open(CONFIG_PATH) as fh:
        return json.load(fh)


class AnalyzerAI(BaseAnalyzer):
    """
    AI-powered mail analyzer.

    Reads the AI model output from self.full / self.summary, enriches
    ChromaDB with the embedding, and creates or updates a TheHive campaign
    alert when the mail is dangerous and part of an active campaign.
    """

    # ── lazy config access ────────────────────────────────────────────────

    @cached_property
    def _config(self) -> Dict[str, Any]:
        return _load_config()

    @cached_property
    def _thehive(self) -> Dict[str, str]:
        cfg = self._config.get("integrations", {}).get("thehive", {})
        return {
            "url": cfg.get("url", ""),
            "key": cfg.get("api_key", ""),
            "verify": bool(cfg.get("certificate_path", True)),
        }

    @cached_property
    def _minio_cfg(self) -> Dict[str, Any]:
        return self._config.get("storage", {}).get("s3", {})

    @cached_property
    def _chromadb_cfg(self) -> Dict[str, Any]:
        return self._config.get("integrations", {}).get("chromadb", {})

    # ── ChromaDB singleton ────────────────────────────────────────────────
    # One client per AnalyzerAI instance — avoids reconnecting on every call.

    @cached_property
    def _chroma_collection(self):
        try:
            client = chromadb.HttpClient(
                host=self._chromadb_cfg.get("host", "chromadb"),
                port=int(self._chromadb_cfg.get("port", 8000)),
            )
            return get_suspicious_collection(client)
        except Exception as exc:
            logger.error("ChromaDB init failed: %s", exc)
            return None

    # ── MinIO client factory ──────────────────────────────────────────────

    def _make_minio_client(self) -> Minio:
        cfg = self._minio_cfg
        return Minio(
            cfg.get("endpoint", ""),
            access_key=cfg.get("access_key", ""),
            secret_key=cfg.get("secret_key", ""),
            secure=bool(cfg.get("secure", False)),
        )

    # ── main entry point ──────────────────────────────────────────────────

    def process(self) -> Dict[str, Any]:
        response = super().process()

        try:
            response = self._apply_base_scoring(response)

            if not self.full:
                return response

            self._merge_details(response)

            malscore = self._get_malscore(response)
            collection = self._chroma_collection

            if malscore <= DANGEROUS_MALSCORE_THRESHOLD:
                logger.info("Mail (case=%s) not dangerous (malscore=%.2f).", self.suspicious_case_id, malscore)
                self._add_to_chroma(collection, alert_id="", source_ref="")
                return response

            logger.info("Mail (case=%s) considered dangerous (malscore=%.2f).", self.suspicious_case_id, malscore)

            self._decode_headers()

            sender_domain = extract_sender_domain_from_headers(
                self.full["report"].get("analyzed_mail_headers", {})
            )
            if sender_domain and is_domain_in_campaign_allow_list(sender_domain):
                logger.info("Sender domain %r is allow-listed — skipping campaign detection.", sender_domain)
                return response   # ← explicit return added

            self._handle_campaign(response, collection)

        except Exception as exc:
            logger.error("AnalyzerAI.process error (case=%s): %s", self.suspicious_case_id, exc, exc_info=True)

        return response

    # ── private helpers ───────────────────────────────────────────────────

    def _apply_base_scoring(self, response: Dict[str, Any]) -> Dict[str, Any]:
        if self.summary:
            try:
                response["score"]      = int(round(float(self.summary.get("malscore",      5))))
                response["confidence"] = int(round(float(self.summary.get("confidence",    0)) * 10))
                response["level"]      = str(self.summary.get("classification", "info")).lower()
            except (TypeError, ValueError) as exc:
                logger.warning("Could not parse AI summary scores: %s", exc)
        response.setdefault("details", {})
        return response

    def _merge_details(self, response: Dict[str, Any]) -> None:
        for key in (
            "classification_probabilities", "report",
            "malscore", "confidence", "classification",
        ):
            if key in self.full:
                response["details"][key] = self.full[key]

    def _get_malscore(self, response: Dict[str, Any]) -> float:
        try:
            return float(response["details"].get("malscore", response.get("score", 5)))
        except (TypeError, ValueError):
            return 5.0

    def _decode_headers(self) -> None:
        try:
            raw = self.full.get("report", {}).get("analyzed_mail_headers", "")
            self.full["report"]["analyzed_mail_headers"] = parse_and_decode_defaultdict(str(raw))
        except Exception as exc:
            logger.error("Header decode error (case=%s): %s", self.suspicious_case_id, exc)

    def _add_to_chroma(
        self,
        collection,
        *,
        alert_id: str,
        source_ref: str,
    ) -> None:
        if collection is None:
            return
        try:
            add_to_suspicious_collection(
                self.full, alert_id, source_ref,
                self.suspicious_case_id, collection,
            )
        except Exception as exc:
            logger.error("add_to_suspicious_collection error (case=%s): %s", self.suspicious_case_id, exc)

    def _handle_campaign(
        self,
        response: Dict[str, Any],
        collection,
    ) -> None:
        hive_url = self._thehive["url"]
        hive_key = self._thehive["key"]
        hive_verify = self._thehive["verify"]

        embedding = response["details"]["report"].get("email_embedding")
        similar   = get_similar_dangerous_mails(embedding, collection) if embedding else {}
        campaign  = get_phishing_campaign(similar)

        if not campaign:
            logger.info("No campaign detected for case %s.", self.suspicious_case_id)
            self._add_to_chroma(collection, alert_id="", source_ref="")
            return

        logger.info("Campaign detected for case %s.", self.suspicious_case_id)

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
        all_case_ids = list(dict.fromkeys(campaign_case_ids + [self.suspicious_case_id]))

        # Create Minio client ONCE before the loop
        minio_client = self._make_minio_client()

        for case_id in all_case_ids:
            self._attach_case_to_alert(
                case_id, alert_id, item_type, minio_client, hive_url, hive_key, hive_verify
            )

        self._add_to_chroma(collection, alert_id=alert_id, source_ref=item.get("sourceRef", ""))

    def _get_or_create_alert(
        self,
        campaign,
        hive_url: str,
        hive_key: str,
    ):
        """
        Return (alert_id, item_type, item_dict).

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

        # Create a new alert
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
            case        = Case.objects.get(id=case_id)
            mail_id     = str(case.fileOrMail.mail.mail_id)
            reporter    = case.reporter.username

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