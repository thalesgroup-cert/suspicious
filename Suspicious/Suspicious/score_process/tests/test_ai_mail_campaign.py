"""Campaign detection must be idempotent, race-free and visible when it fails."""
import json
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import SimpleTestCase

from connectors.contrib.thehive.phishing import TheHivePushError
from score_process.score_utils.chromadb_utils import add_to_suspicious_collection
from score_process.scoring.cortex_analyzers.contrib import ai_mail
from score_process.scoring.cortex_analyzers.contrib.ai_mail import AiMailParser

FULL = {
    "classification": "DANGEROUS", "sub_classification": "Phishing", "malscore": 9.0, "confidence": 0.9,
    "report": {"analyzed_mail_content": "pay now", "email_embedding": json.dumps([[0.1, 0.2]]),
               "analyzed_mail_headers": {"Subject": ["Pay"]}},
}
M = "score_process.scoring.cortex_analyzers.contrib.ai_mail"


def _parser(case_id=7):
    p = AiMailParser.__new__(AiMailParser)
    p.case_id, p.full = case_id, FULL
    p.__dict__["_thehive"] = {"url": "http://hive", "key": "k", "verify": True}
    return p


class ChromaIdempotenceTest(SimpleTestCase):
    def test_same_case_is_stored_once(self):
        store = {}

        class Coll:
            def get(self, ids):
                return {"ids": [i for i in ids if i in store]}

            def add(self, ids, **kw):
                assert ids not in store, "duplicate id"
                store[ids] = kw

        coll = Coll()
        add_to_suspicious_collection(FULL, "", "", 7, coll)
        add_to_suspicious_collection(FULL, "", "", 7, coll)  # reconcile re-parses the report
        self.assertEqual(len(store), 1)


class SideEffectGuardTest(SimpleTestCase):
    def test_no_campaign_work_without_a_case(self):
        # the job-finished scoring pass has no case; it must not touch Chroma/TheHive
        p = _parser(case_id=None)
        with patch.object(AiMailParser, "_handle_campaign") as handle, \
                patch.object(AiMailParser, "_add_to_chroma") as add:
            p._run_campaign(MagicMock())
        handle.assert_not_called()
        add.assert_not_called()


class RaceTest(SimpleTestCase):
    def setUp(self):
        cache.delete("thehive:campaign-alert")

    def test_alert_created_by_another_worker_is_reused(self):
        p = _parser()
        meta = {"suspicious_case_id": "3", "alert_ids": "[]", "headers": "{'Subject': ['Pay']}"}
        no_alert = {"ids": [["a"]], "metadatas": [[meta]], "distances": [[0.1]]}
        with_alert = {"ids": [["a"]], "metadatas": [[dict(meta, alert_ids='["~1"]')]], "distances": [[0.1]]}
        queries = iter([no_alert, with_alert])
        campaign = {"ids": [["a"]], "metadatas": [[meta]], "documents": [[""]], "embeddings": [[[0]]],
                    "distances": [[0.1]]}
        campaign_with_alert = dict(campaign, metadatas=[[dict(meta, alert_ids='["~1"]')]])
        result = MagicMock()
        result.details = {"report": {"email_embedding": json.dumps([[0.1]])}}
        with patch(f"{M}.get_similar_dangerous_mails", side_effect=lambda *a, **k: next(queries)), \
                patch(f"{M}.get_phishing_campaign", side_effect=[campaign, campaign_with_alert]), \
                patch(f"{M}.create_new_alert") as create, \
                patch(f"{M}.get_item_from_id", return_value=("alert", {"sourceRef": "r"})), \
                patch(f"{M}.update_suspicious_collection"), \
                patch.object(AiMailParser, "_attach_case_to_alert"), \
                patch.object(AiMailParser, "_add_to_chroma"), \
                patch.object(AiMailParser, "_make_minio_client"):
            p._handle_campaign(result, MagicMock())
        create.assert_not_called()


class CreateFailureTest(SimpleTestCase):
    def test_failed_alert_creation_is_an_explicit_error(self):
        p = _parser()
        campaign = {"ids": [[]], "metadatas": [[]], "documents": [[]], "embeddings": [[]], "distances": [[]]}
        with patch(f"{M}.get_most_common_alert_id", return_value=""), \
                patch(f"{M}.get_most_common_subject", return_value="s"), \
                patch(f"{M}.create_new_alert", return_value=None):
            with self.assertRaises(TheHivePushError):
                p._get_or_create_alert(campaign, "http://hive", "k")


class AttachStepsTest(SimpleTestCase):
    def test_a_failed_zip_upload_does_not_skip_the_observables(self):
        p = _parser()
        case = MagicMock()
        case.fileOrMail.mail.mail_id = "261007071836-aaa"
        case.reporter.username = "u"
        with patch(f"{M}.Case") as case_model, \
                patch(f"{M}.build_mail_zip_from_minio", return_value=("z.zip", b"PKdata")), \
                patch(f"{M}.fetch_mail_files_from_minio", return_value=("H", "", "", "<a href='http://x.example'>")), \
                patch(f"{M}.add_binary_attachment_to_item", side_effect=RuntimeError("403 manageAlert/update")), \
                patch(f"{M}.add_observables_to_item") as add_obs, \
                patch(f"{M}.build_mail_observables_from_headers", return_value=[{"dataType": "mail"}]), \
                patch(f"{M}.build_mail_observables_from_html", return_value=[{"dataType": "url"}]):
            case_model.objects.get.return_value = case
            case_model.DoesNotExist = type("DoesNotExist", (Exception,), {})
            with self.assertLogs("tasp.cron.update_ongoing_case_jobs", level="WARNING") as logs:
                p._attach_case_to_alert(7, "~1", "alert", MagicMock(), "http://hive", "k")
        self.assertEqual(add_obs.call_count, 2)
        self.assertTrue(any("attachment" in line.lower() and "403" in line for line in logs.output))
