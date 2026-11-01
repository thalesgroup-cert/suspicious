import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone as tz

from django.contrib.auth import get_user_model
from django.test import TestCase

from ai_model import ledger
from ai_model.messageid import message_id_hash
from ai_model.models import AiAssessment, LabelRecord
from case_handler.models import Case, CaseHasFileOrMail
from connectors.contrib.ai_model.imap_sync import ReviewMail
from mail_feeder.models import Mail, MailHeader

DATE = datetime(2026, 5, 1, 10, tzinfo=tz.utc)
VECTORS = {"classifier": [0.1, 0.2], "campaign": [0.3, 0.4]}
VERSIONS = {"preprocessing_version": "legacy-first128", "embedding_version": "cmp-e1"}


def review(folder="2_CLASSIC_PHISHING", message_id="abc.1@evil.example", uid=5, **kw):
    fields = dict(folder=folder, uidvalidity=7, uid=uid, message_id=message_id, sender="bob@evil.example",
                  date=DATE, subject="Urgent: verify", text="body")
    fields.update(kw)
    return ReviewMail(**fields)


def observe(mail):
    observation = ledger.prepare_folder_observation(mail)
    return observation and ledger.record_folder_observation(observation, VECTORS, **VERSIONS)


class RecordFolderObservationTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="u", password="x")

    def make_case(self, message_id="<ABC.1@Evil.Example>", **case_fields):
        d = defaultdict(list)
        d["Message-ID"].append(message_id)
        d["From"].append("Bob <bob@Evil.Example>")
        header = MailHeader.objects.create(header_value=str(d), fuzzy_hash="h1")
        mail = Mail.objects.create(subject="Urgent: verify", reportedBy="r", date=DATE, to="t", mail_id="m1",
                                   mail_header=header)
        case = Case.objects.create(description="", reporter=self.user, **case_fields)
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save(update_fields=["fileOrMail"])
        return case

    def test_creates_active_folder_row_with_case_vectors_and_snapshot(self):
        case = self.make_case(is_denylisted=True)
        AiAssessment.objects.create(case=case, model_version="v0", result="DANGEROUS", score=8, confidence=90)
        row = observe(review())
        self.assertEqual((row.source, row.trust, row.status, row.label, row.label_class),
                         ("imap_folder", "folder", "active", "2_CLASSIC_PHISHING", "Dangerous"))
        self.assertEqual((row.message_id, row.message_id_hash),
                         ("abc.1@evil.example", message_id_hash("abc.1@evil.example")))
        self.assertEqual(row.case, case)
        self.assertEqual(row.source_ref, "2_CLASSIC_PHISHING:7:5")
        self.assertEqual((json.loads(row.embedding), json.loads(row.campaign_embedding)), ([0.1, 0.2], [0.3, 0.4]))
        self.assertEqual((row.preprocessing_version, row.embedding_version), ("legacy-first128", "cmp-e1"))
        self.assertEqual(row.snapshot, {
            "sender_domain": "evil.example", "subject_length": 14, "is_allowlisted": False,
            "is_denylisted": True, "ai_result": "DANGEROUS", "ai_model_version": "v0",
        })
        self.assertTrue(row.trainable)

    def test_same_message_same_folder_adds_nothing(self):
        observe(review())
        self.assertIsNone(observe(review(uid=99, uidvalidity=8)))
        self.assertEqual(LabelRecord.objects.count(), 1)

    def test_other_folder_appends_and_supersedes(self):
        old = observe(review())
        new = observe(review(folder="0_LEGIT_EXTERNAL_COMMUNICATION"))
        old.refresh_from_db()
        self.assertEqual((old.status, new.status, new.label_class), ("superseded", "active", "Safe"))
        self.assertEqual(LabelRecord.objects.count(), 2)

    def test_unmatched_mail_has_no_case_and_a_snapshot_from_the_review_mail(self):
        row = observe(review(message_id="nobody@nowhere.example"))
        self.assertIsNone(row.case)
        self.assertEqual(row.snapshot["sender_domain"], "evil.example")
        self.assertIsNone(row.snapshot["ai_result"])

    def test_inner_message_id_is_a_match_fallback(self):
        case = self.make_case(message_id="<inner.1@evil.example>")
        row = observe(review(message_id="nobody@nowhere.example", inner_message_ids=("inner.1@evil.example",)))
        self.assertEqual(row.case, case)

    def test_no_message_id_matches_on_sender_date_subject_and_keys_on_the_content(self):
        case = self.make_case()
        row = observe(review(message_id=""))
        self.assertEqual((row.case, row.message_id), (case, ""))
        key = ("no-message-id:bob@evil.example|2026-05-01T10:00:00+00:00|urgent: verify|"
               + hashlib.sha256(b"body").hexdigest())
        self.assertEqual(row.message_id_hash, message_id_hash(key))
        self.assertEqual(LabelRecord.objects.get().source_ref, "2_CLASSIC_PHISHING:7:5")

    def test_no_message_id_survives_a_uidvalidity_reset_and_a_move(self):
        first = observe(review(message_id=""))
        self.assertIsNone(observe(review(message_id="", uid=40, uidvalidity=8)))
        moved = observe(review(message_id="", folder="1_SPAM", uid=3))
        first.refresh_from_db()
        self.assertEqual((first.status, moved.status), ("superseded", "active"))
        self.assertIsNotNone(observe(review(message_id="", uid=6, text="another body")))

    def test_moved_back_reactivates_the_first_folder(self):
        a = observe(review())
        b = observe(review(folder="1_SPAM"))
        again = observe(review(uid=77))
        a.refresh_from_db(), b.refresh_from_db()
        self.assertEqual((a.status, b.status, again.status), ("superseded", "superseded", "active"))
        self.assertEqual(again.label, "2_CLASSIC_PHISHING")

    def test_a_flagged_row_reread_adds_no_trainable_row(self):
        row = observe(review())
        LabelRecord.objects.filter(pk=row.pk).update(status="flagged", flag_reason="verdict_conflict")
        self.assertIsNone(observe(review(uid=78)))
        self.assertFalse(any(r.trainable for r in LabelRecord.objects.all()))

    def test_record_rechecks_for_a_concurrent_write(self):
        observation = ledger.prepare_folder_observation(review())
        observe(review())  # another run got there between the pre-pass and the write
        self.assertIsNone(ledger.record_folder_observation(observation, VECTORS, **VERSIONS))
        self.assertEqual(LabelRecord.objects.count(), 1)

    def test_prepare_does_the_matching_and_the_snapshot(self):
        case = self.make_case()
        observation = ledger.prepare_folder_observation(review())
        self.assertEqual((observation.case, observation.snapshot["sender_domain"]), (case, "evil.example"))
        observe(review())
        self.assertIsNone(ledger.prepare_folder_observation(review(uid=9)))
        self.assertIsNone(ledger.prepare_folder_observation(review(folder="9_ODD")))
