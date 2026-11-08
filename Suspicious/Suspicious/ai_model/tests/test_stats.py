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
        return ModelVersionStats.objects.get(version=version or self.v0, day=timezone.localdate())

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
        materialise_model_stats()
        self.assertEqual(self.row().scored, 3)

    def test_a_version_without_data_has_no_rows_and_old_days_are_left_alone(self):
        self.case(version="s1")  # no ModelVersion row: skipped
        old = ModelVersionStats.objects.create(version=self.v0, day=timezone.localdate() - timedelta(days=10), scored=7)
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

    def test_two_versions_backdated_rows_and_the_window_edge(self):
        v1 = ModelVersion.objects.create(version_id="s1", status="candidate", trigger="manual")
        now = timezone.now()

        def back(case, days):
            AiAssessment.objects.filter(case=case).update(created_at=now - timedelta(days=days))

        today_s1 = self.case("s1", "DANGEROUS")
        yesterday = self.case("v0")
        back(yesterday, 1)
        edge = self.case("v0")  # 4 days old: outside the 3-day window
        back(edge, 4)
        ConnectorDelivery.objects.create(connector="ai_model", event="case_finalised", case_id=yesterday.id, status="success")
        ConnectorDelivery.objects.filter(case_id=yesterday.id).update(created_at=now - timedelta(days=1))
        old = ModelVersionStats.objects.create(version=self.v0, day=timezone.localdate() - timedelta(days=4), scored=9)
        materialise_model_stats()
        y = ModelVersionStats.objects.get(version=self.v0, day=timezone.localdate() - timedelta(days=1))
        self.assertEqual((y.scored, y.campaign_checks), (1, 1))
        t = self.row(v1)
        self.assertEqual((t.scored, t.dangerous, t.campaign_checks), (1, 1, 0))
        self.assertFalse(ModelVersionStats.objects.filter(version=self.v0, day=timezone.localdate()).exists())
        old.refresh_from_db()
        self.assertEqual(old.scored, 9)
        self.assertEqual(ModelVersionStats.objects.count(), 3)
        self.assertIsNotNone(today_s1)

    def test_exact_edges(self):
        self.labelled(self.v0, "Dangerous", 8)
        self.labelled(self.v0, "Safe", 2)
        p = stats.purity(self.v0)
        self.assertEqual((p["labelled"], p["purity"], p["warning"]), (10, 0.8, False))
        base = self.v0.created_at
        self.assertFalse(stats.age_warning(self.v0, now=base + timedelta(days=60)))
        self.assertTrue(stats.age_warning(self.v0, now=base + timedelta(days=61)))

    def test_purity_many_keeps_versions_apart_with_overlapping_labels(self):
        v1 = ModelVersion.objects.create(version_id="s1", status="candidate", trigger="manual")
        self.labelled(self.v0, "Dangerous", 3)
        self.labelled(self.v0, "Safe", 7)
        self.labelled(v1, "Dangerous", 4)
        shared = CampaignMember.objects.filter(case__ai_assessment__model_version="v0").first().case
        LabelRecord.objects.create(message_id="m", message_id_hash="h", case=shared, source="analyst_verdict",
                                   label="Safe", label_class="Safe", trust="verdict")  # relabelled: latest wins
        many = stats.purity_many([self.v0, v1])
        self.assertEqual(many["v0"], stats.purity(self.v0))
        self.assertEqual(many["s1"], stats.purity(v1))
        self.assertEqual((many["v0"]["labelled"], many["v0"]["warning"]), (10, True))
        self.assertEqual((many["s1"]["labelled"], many["s1"]["dangerous"], many["s1"]["warning"]), (4, 4, False))
        self.assertLessEqual(many["v0"]["dangerous"], 3)

    def test_totals_are_zero_for_a_version_without_rows(self):
        v1 = ModelVersion.objects.create(version_id="s1", status="candidate", trigger="manual")
        ModelVersionStats.objects.create(version=self.v0, day=timezone.localdate(), scored=5, dangerous=2, created=1)
        t = stats.totals([self.v0, v1])
        self.assertEqual(t["s1"], {"scored": 0, "dangerous": 0, "checks": 0, "joined": 0, "alerts": 0, "created": 0})
        self.assertEqual((t["v0"]["scored"], t["v0"]["dangerous"], t["v0"]["created"]), (5, 2, 1))
