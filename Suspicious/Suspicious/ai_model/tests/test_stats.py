from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from ai_model import registry, stats
from ai_model.models import AiAssessment, LabelRecord, ModelVersion, ModelVersionStats
from ai_model.tasks import materialise_model_stats
from case_handler.models import Campaign, CampaignMember
from connectors.models import ConnectorDelivery
from connectors.tests.test_provider_dispatch import make_mail_case


class StatsTest(TestCase):
    def setUp(self):
        self.v0 = registry.ensure_version_zero()
        self.n = 0

    def case(self, version="v0", result="SAFE"):
        self.n += 1
        case, _ = make_mail_case(self.n)
        AiAssessment.objects.create(case=case, model_version=version, result=result, score=1, confidence=1)
        return case

    def row(self, version=None):
        return ModelVersionStats.objects.get(version=version or self.v0, day=timezone.now().date())

    def test_counters_per_version_and_day(self):
        a, b, c = self.case(result="DANGEROUS"), self.case(result="DANGEROUS"), self.case()
        camp = Campaign.objects.create()
        CampaignMember.objects.create(campaign=camp, case=a)
        CampaignMember.objects.create(campaign=camp, case=b)
        ConnectorDelivery.objects.create(connector="ai_model", event="case_finalised", case_id=a.id, status="success")
        ConnectorDelivery.objects.create(connector="ai_model", event="case_finalised", case_id=b.id, status="failed")
        ConnectorDelivery.objects.create(connector="thehive", event="campaign_updated", case_id=b.id, status="success")
        ConnectorDelivery.objects.create(connector="thehive", event="other", case_id=b.id, status="success")
        materialise_model_stats()
        materialise_model_stats()  # idempotent
        r = self.row()
        self.assertEqual((r.scored, r.dangerous, r.campaign_checks, r.created, r.joined, r.alerts),
                         (3, 2, 1, 1, 1, 1))
        self.assertEqual(ModelVersionStats.objects.count(), 1)

    def test_a_version_without_data_has_no_rows_and_old_days_are_left_alone(self):
        self.case(version="s1")  # no ModelVersion row: skipped
        old = ModelVersionStats.objects.create(version=self.v0, day=timezone.now().date() - timedelta(days=10), scored=7)
        materialise_model_stats()
        self.assertEqual(list(ModelVersionStats.objects.all()), [old])

    def labelled(self, version, klass, n):
        for _ in range(n):
            case = self.case(version.version_id)
            CampaignMember.objects.create(campaign=Campaign.objects.create(), case=case)
            LabelRecord.objects.create(message_id="m", message_id_hash="h", case=case, source="analyst_verdict",
                                       label=klass, label_class=klass, trust="verdict")

    def test_purity_warning_needs_ten_labelled_and_under_80_percent(self):
        self.labelled(self.v0, "Dangerous", 7)
        self.labelled(self.v0, "Safe", 2)
        p = stats.purity(self.v0)
        self.assertEqual((p["labelled"], p["dangerous"], p["warning"]), (9, 7, False))
        self.labelled(self.v0, "Safe", 1)
        p = stats.purity(self.v0)
        self.assertEqual((p["labelled"], p["purity"], p["warning"]), (10, 0.7, True))
        self.labelled(self.v0, "Dangerous", 10)
        self.assertFalse(stats.purity(self.v0)["warning"])  # 17/20 = 85%

    def test_purity_ignores_inactive_labels_and_old_members(self):
        self.labelled(self.v0, "Safe", 10)
        LabelRecord.objects.update(status="superseded")
        self.assertEqual(stats.purity(self.v0)["labelled"], 0)
        self.assertIsNone(stats.purity(self.v0)["purity"])
        LabelRecord.objects.update(status="active")
        CampaignMember.objects.update(joined_at=timezone.now() - timedelta(days=31))
        self.assertEqual(stats.purity(self.v0)["labelled"], 0)
        self.assertEqual(stats.purity(self.v0, now=timezone.now() + timedelta(days=2))["labelled"], 0)

    def test_age_warning_at_sixty_days_from_creation(self):
        self.assertFalse(stats.age_warning(self.v0))
        self.assertTrue(stats.age_warning(self.v0, now=timezone.now() + timedelta(days=61)))
