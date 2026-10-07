"""Campaign detection must be idempotent, race-free and visible when it fails."""
import json
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import SimpleTestCase

from connectors.contrib.thehive.phishing import TheHivePushError
from score_process.score_utils.chromadb_utils import add_to_suspicious_collection
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


class AttachScopeTest(SimpleTestCase):
    """A new alert gets every campaign case; joining an existing one only the new case."""

    def _run(self, similar_case_ids, existing_alert):
        p = _parser(case_id=9)
        def meta(cid, alerts):
            return {"suspicious_case_id": str(cid), "alert_ids": alerts, "headers": "{'Subject': ['Pay']}"}

        alerts = '["", "~1"]' if existing_alert else '[""]'
        similar = {"ids": [[f"d{c}" for c in similar_case_ids]],
                   "metadatas": [[meta(c, alerts) for c in similar_case_ids]],
                   "documents": [["" for _ in similar_case_ids]],
                   "embeddings": [[[0] for _ in similar_case_ids]],
                   "distances": [[0.1 for _ in similar_case_ids]]}
        result = MagicMock()
        result.details = {"report": {"email_embedding": json.dumps([[0.1]])}}
        with patch(f"{M}.get_similar_dangerous_mails", return_value=similar), \
                patch(f"{M}.create_new_alert", return_value={"_id": "~new", "sourceRef": "r"}), \
                patch(f"{M}.get_item_from_id", return_value=("alert", {"sourceRef": "r"})), \
                patch(f"{M}.update_suspicious_collection"), \
                patch.object(AiMailParser, "_attach_case_to_alert") as attach, \
                patch.object(AiMailParser, "_add_to_chroma"), \
                patch.object(AiMailParser, "_make_minio_client"):
            p._handle_campaign(result, MagicMock())
        return sorted(c.args[0] for c in attach.call_args_list)

    def test_new_alert_attaches_every_campaign_case(self):
        self.assertEqual(self._run([1, 2, 3], existing_alert=False), [1, 2, 3, 9])

    def test_joining_an_alert_attaches_only_the_new_case(self):
        self.assertEqual(self._run([1, 2, 3], existing_alert=True), [9])


class AttachOnceTest(SimpleTestCase):
    """The creator, the case's own pass and every reconcile all try to attach a
    case; it must reach the alert exactly once."""

    def _attach(self, *, already, fail=False):
        p = _parser()
        case = MagicMock(thehive_alert_id="~1" if already else "")
        case.fileOrMail.mail.mail_id = "261007071836-aaa"
        case.reporter.username = "u"
        upload = MagicMock(side_effect=RuntimeError("403") if fail else None)
        with patch(f"{M}.Case") as case_model, \
                patch(f"{M}.build_mail_zip_from_minio", return_value=("z.zip", b"PK")), \
                patch(f"{M}.fetch_mail_files_from_minio", return_value=("", "", "", "")), \
                patch(f"{M}.add_binary_attachment_to_item", upload):
            case_model.objects.get.return_value = case
            case_model.DoesNotExist = type("DoesNotExist", (Exception,), {})
            cache.delete("thehive:attach:7")
            p._attach_case_to_alert(7, "~1", "alert", MagicMock(), "http://hive", "k")
        return case, upload

    def test_already_attached_case_is_skipped(self):
        _case, upload = self._attach(already=True)
        upload.assert_not_called()

    def test_success_marks_the_case_attached(self):
        case, upload = self._attach(already=False)
        upload.assert_called_once()
        self.assertEqual(case.thehive_alert_id, "~1")
        case.save.assert_called_with(update_fields=["thehive_alert_id"])

    def test_failure_leaves_it_unmarked_so_the_next_pass_retries(self):
        case, _upload = self._attach(already=False, fail=True)
        self.assertEqual(case.thehive_alert_id, "")
        case.save.assert_not_called()
