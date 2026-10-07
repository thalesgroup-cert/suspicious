import json
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase

from case_handler import campaigns
from case_handler.models import Campaign, CampaignMember, Case

C = "case_handler.campaigns"


def _case():
    user, _ = get_user_model().objects.get_or_create(username="rep", defaults={"email": "r@e.c"})
    return Case.objects.create(reporter=user, description="t")


def _full(malscore=9.0):
    return {
        "classification": "DANGEROUS", "sub_classification": "Phishing",
        "malscore": malscore, "confidence": 0.9,
        "report": {"analyzed_mail_content": "pay now", "email_embedding": json.dumps([[0.1, 0.2]]),
                   "analyzed_mail_headers": {"Subject": ["Verify payroll"], "From": ["a@evil.example"]}},
    }


class FakeCollection:
    def __init__(self):
        self.docs = {}

    def get(self, ids=None, include=None):
        ids = [i for i in (ids or []) if i in self.docs]
        return {"ids": ids, "metadatas": [self.docs[i] for i in ids]}

    def add(self, ids, metadatas, **kw):
        self.docs[ids] = dict(metadatas[0])

    def update(self, ids, metadatas):
        ids = [ids] if isinstance(ids, str) else ids
        metas = [metadatas] if isinstance(metadatas, dict) else metadatas
        for i, m in zip(ids, metas):
            self.docs[i] = dict(m)


def _similar(case_ids):
    meta = lambda cid: {"suspicious_case_id": str(cid), "alert_ids": '[""]',
                        "headers": "{'Subject': ['Verify payroll']}", "sourceRefs": '[""]'}
    return {"ids": [[f"case-{c}" for c in case_ids]], "metadatas": [[meta(c) for c in case_ids]],
            "documents": [["" for _ in case_ids]], "embeddings": [[[0] for _ in case_ids]],
            "distances": [[0.1 for _ in case_ids]]}


class DetectionTest(TestCase):
    def setUp(self):
        cache.delete("campaign:detect")
        self.coll = FakeCollection()
        for target, value in (
            (f"{C}.get_chroma_client", MagicMock()),
            (f"{C}.get_suspicious_collection", MagicMock(return_value=self.coll)),
        ):
            p = patch(target, value); p.start(); self.addCleanup(p.stop)

    def _detect(self, case, full, similar=None):
        with patch(f"{C}.ai_full_report", return_value=full), \
                patch(f"{C}.get_similar_dangerous_mails", return_value=similar or {}):
            return campaigns.detect_campaign(case)

    def test_low_malscore_is_stored_but_not_a_campaign(self):
        case = _case()
        self.assertIsNone(self._detect(case, _full(malscore=3.0)))
        self.assertIn(f"case-{case.id}", self.coll.docs)

    def test_too_few_similar_mails_is_not_a_campaign(self):
        a, b, case = _case(), _case(), _case()
        self.assertIsNone(self._detect(case, _full(), _similar([a.id, b.id])))
        self.assertEqual(Campaign.objects.count(), 0)
        self.assertIn(f"case-{case.id}", self.coll.docs)

    def test_three_similar_mails_create_a_campaign_with_all_members(self):
        old = [_case() for _ in range(3)]
        for c in old:
            self.coll.docs[f"case-{c.id}"] = {"suspicious_case_id": str(c.id), "sourceRefs": '[""]'}
        case = _case()
        campaign = self._detect(case, _full(), _similar([c.id for c in old]))
        self.assertIsNotNone(campaign)
        self.assertEqual(campaign.title, "Verify payroll")
        self.assertEqual(set(campaign.members.values_list("case_id", flat=True)),
                         {c.id for c in old} | {case.id})
        # the Campaigns page groups ChromaDB documents by sourceRefs
        for c in old + [case]:
            self.assertEqual(json.loads(self.coll.docs[f"case-{c.id}"]["sourceRefs"]), [campaign.ref])

    def test_similar_mails_of_an_existing_campaign_join_it(self):
        old = [_case() for _ in range(3)]
        campaign = Campaign.objects.create(title="x")
        for c in old:
            CampaignMember.objects.create(campaign=campaign, case=c)
        case = _case()
        self.assertEqual(self._detect(case, _full(), _similar([c.id for c in old])), campaign)
        self.assertEqual(Campaign.objects.count(), 1)
        self.assertEqual(campaign.members.count(), 4)

    def test_a_case_already_in_a_campaign_is_left_alone(self):
        case = _case()
        CampaignMember.objects.create(campaign=Campaign.objects.create(title="x"), case=case)
        with patch(f"{C}.ai_full_report") as report:
            self.assertIsNone(campaigns.detect_campaign(case))
        report.assert_not_called()

    def test_no_ai_report_means_no_detection(self):
        self.assertIsNone(self._detect(_case(), None))

    def test_allow_listed_sender_domain_is_skipped(self):
        case = _case()
        with patch(f"{C}.is_domain_in_campaign_allow_list", return_value=True):
            self.assertIsNone(self._detect(case, _full(), _similar([1, 2, 3])))
        self.assertNotIn(f"case-{case.id}", self.coll.docs)

    def test_chroma_failure_is_contained(self):
        with patch(f"{C}.get_suspicious_collection", side_effect=RuntimeError("chroma down")):
            self.assertIsNone(self._detect(_case(), _full()))


class RunForCaseTest(TestCase):
    def test_emits_campaign_updated_when_a_campaign_is_found(self):
        case = _case()
        campaign = Campaign.objects.create(title="x")
        with patch(f"{C}.detect_campaign", return_value=campaign), patch(f"{C}.emit") as emit:
            campaigns.run_for_case(case)
        emit.assert_called_once_with("campaign_updated", case, campaign_id=campaign.id)

    def test_nothing_is_emitted_otherwise_and_errors_do_not_escape(self):
        case = _case()
        with patch(f"{C}.detect_campaign", return_value=None), patch(f"{C}.emit") as emit:
            campaigns.run_for_case(case)
        emit.assert_not_called()
        with patch(f"{C}.detect_campaign", side_effect=RuntimeError("boom")):
            campaigns.run_for_case(case)  # must not raise: finalisation continues
