from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from ai_model import queue
from ai_model.models import AiAssessment, LabelRecord
from ai_model.tests.test_ledger import CaseMixin
from case_handler.models import Campaign, CampaignMember, Case

CLASSIC = {"decisive_rule": "deny-listed", "band": "Safe"}
AI_DECIDED = {"decisive_rule": "ai-classifier-decisive", "band": "Safe"}


class DisagreementsTest(CaseMixin, TestCase):
    def finalised(self, result="DANGEROUS", explanation=CLASSIC, days=1, mail=True):
        kw = dict(results="Safe", verdict_explanation=explanation, finalized_at=timezone.now() - timedelta(days=days))
        case = self.make_case(**kw) if mail else Case.objects.create(description="", reporter=self.user, **kw)
        AiAssessment.objects.create(case=case, model_version="v0", result=result, score=1, confidence=1)
        return case

    def test_lists_only_independent_recent_mail_disagreements(self):
        keep = self.finalised()
        self.finalised(explanation=AI_DECIDED)
        self.finalised(days=45)
        self.finalised(mail=False)
        self.finalised(result="SAFE")
        rows = queue.disagreements()
        self.assertEqual([r["case_id"] for r in rows], [keep.pk])
        self.assertEqual(set(rows[0]), {"case_id", "verdict", "ai_class", "date"})
        self.assertEqual((rows[0]["verdict"], rows[0]["ai_class"]), ("Safe", "Dangerous"))

    def test_cap(self):
        for _ in range(3):
            self.finalised()
        self.assertEqual(len(queue.disagreements(cap=2)), 2)


class ConflictsTest(TestCase):
    def campaign(self, *classes):
        user = get_user_model().objects.create_user(username=f"u{Campaign.objects.count()}", password="x")
        campaign = Campaign.objects.create()
        for i, label in enumerate(classes):
            case = Case.objects.create(description="", reporter=user)
            CampaignMember.objects.create(campaign=campaign, case=case)
            LabelRecord.objects.create(
                message_id_hash=f"{campaign.ref}{i}", case=case, source=LabelRecord.Source.IMAP_FOLDER,
                label=label, label_class=label, trust=LabelRecord.Trust.FOLDER)
        return campaign

    def test_only_campaigns_with_opposite_labels(self):
        bad = self.campaign("Dangerous", "Safe")
        self.campaign("Dangerous", "Dangerous")
        self.campaign("Dangerous", "Unwanted")
        rows = queue.campaign_conflicts()
        self.assertEqual([r["campaign_ref"] for r in rows], [bad.ref])
        self.assertEqual(set(rows[0]), {"campaign_ref", "classes", "date"})
        self.assertEqual(rows[0]["classes"], ["Dangerous", "Safe"])

    def test_cap(self):
        for _ in range(3):
            self.campaign("Dangerous", "Safe")
        self.assertEqual(len(queue.campaign_conflicts(cap=2)), 2)
