from django.contrib.auth import get_user_model
from django.test import TestCase

from ai_model.models import AiAssessment
from ai_model.presentation import _campaign, cross_check, present_assessment
from case_handler.models import Campaign, CampaignMember, Case

EXPLANATION = {
    "decisive_rule": "deny-listed",
    "band": "Dangerous",
    "sources": [
        {"name": "VirusTotal", "verdict": "malicious", "counted": True},
        {"name": "x", "verdict": "clean", "counted": False},
    ],
}


class PresentAssessmentTest(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.user = users.create_user(username="u", password="pass")
        self.other = users.create_user(username="o", password="pass")
        self.case = Case.objects.create(description="", reporter=self.user)

    def _assess(self, case=None, **kw):
        fields = {"model_version": "v0", "result": "DANGEROUS", "score": 9, "confidence": 90}
        fields.update(kw)
        return AiAssessment.objects.create(case=case or self.case, **fields)

    def _present(self):
        return present_assessment(Case.objects.get(pk=self.case.pk), self.user)

    def test_no_assessment_gives_none(self):
        self.assertIsNone(self._present())

    def test_version_0_has_no_tier_and_no_runner_up(self):
        a = self._assess(tier="", probabilities={"DANGEROUS": 0.5, "SAFE": 0.4})
        out = self._present()
        self.assertEqual(out["tier"], "")
        self.assertIsNone(out["runner_up"])
        self.assertEqual(out["result"], "Dangerous")
        self.assertEqual(out["model_version"], "v0")
        self.assertEqual(out["analysed_at"], a.updated_at)
        self.assertEqual(out["reads"], "body only")

    def test_low_tier_names_the_runner_up(self):
        self._assess(
            result="Dangerous",
            tier="low",
            probabilities={"Dangerous": 0.48, "Safe": 0.42, "Unwanted": 0.10},
        )
        self.assertEqual(self._present()["runner_up"], {"result": "Safe"})

    def test_uppercase_storage_is_shown_in_title_case(self):
        self._assess(tier="low", probabilities={"DANGEROUS": 0.48, "UNWANTED": 0.42, "SAFE": 0.1})
        out = self._present()
        self.assertEqual((out["result"], out["runner_up"]), ("Dangerous", {"result": "Unwanted"}))

    def test_high_tier_has_no_runner_up(self):
        self._assess(tier="high", probabilities={"Dangerous": 0.9, "Safe": 0.1})
        self.assertIsNone(self._present()["runner_up"])

    def test_similar_case_the_viewer_cannot_open_is_dropped(self):
        mine = Case.objects.create(description="", reporter=self.user)
        hidden = Case.objects.create(description="", reporter=self.other)
        entry = {"similarity": 0.9, "label": "Dangerous", "provenance": "analyst"}
        self._assess(similar_cases=[{**entry, "case_id": hidden.pk}, {**entry, "case_id": mine.pk}])
        self.assertEqual(self._present()["similar_cases"], [{**entry, "case_id": mine.pk}])

    def test_campaign_reference_and_size(self):
        self._assess()
        campaign = Campaign.objects.create()
        CampaignMember.objects.create(campaign=campaign, case=self.case)
        for _ in range(2):
            other = Case.objects.create(description="", reporter=self.other)
            CampaignMember.objects.create(campaign=campaign, case=other)
        self.assertEqual(self._present()["campaign"], {"ref": campaign.ref, "size": 3})

    def test_prefetched_campaign_size_runs_no_query(self):
        self._assess()
        campaign = Campaign.objects.create()
        CampaignMember.objects.create(campaign=campaign, case=self.case)
        case = (
            Case.objects.select_related("ai_assessment")
            .prefetch_related("campaign_membership__campaign__members")
            .get(pk=self.case.pk)
        )
        with self.assertNumQueries(0):
            self.assertEqual(_campaign(case), {"ref": campaign.ref, "size": 1})

    def test_case_outside_a_campaign_has_no_campaign(self):
        self._assess()
        self.assertIsNone(self._present()["campaign"])


class CrossCheckTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="u", password="pass")

    def _check(self, result, explanation, **case_fields):
        case = Case.objects.create(
            description="", reporter=self.user, verdict_explanation=explanation, **case_fields
        )
        a = AiAssessment.objects.create(
            case=case, model_version="v0", result=result, score=0, confidence=0
        )
        return cross_check(case, a)

    def test_facts_from_rule_counted_sources_and_list(self):
        out = self._check(
            "DANGEROUS", EXPLANATION, is_denylisted=True, list_reason="bad.example"
        )
        self.assertEqual([f["kind"] for f in out["facts"]], ["rule", "source", "list"])
        self.assertEqual(out["facts"][0]["text"], "Decisive rule: deny-listed")
        self.assertIn("VirusTotal", out["facts"][1]["text"])
        self.assertIn("bad.example", out["facts"][2]["text"])

    def test_safe_ai_against_dangerous_band_disagrees(self):
        self.assertTrue(self._check("SAFE", {"band": "Dangerous"})["disagrees"])

    def test_dangerous_ai_against_safe_band_disagrees(self):
        self.assertTrue(self._check("DANGEROUS", {"band": "Safe"})["disagrees"])

    def test_same_side_agrees(self):
        self.assertFalse(self._check("DANGEROUS", {"band": "Dangerous"})["disagrees"])
        self.assertFalse(self._check("SAFE", {"band": "Safe"})["disagrees"])

    def test_off_axis_classes_never_disagree(self):
        self.assertFalse(self._check("UNWANTED", {"band": "Safe"})["disagrees"])
        self.assertFalse(self._check("DANGEROUS", {"band": "Suspicious"})["disagrees"])
        self.assertFalse(self._check("INCONCLUSIVE", {"band": "Dangerous"})["disagrees"])

    def test_no_explanation_gives_no_rule_or_source_and_no_disagreement(self):
        out = self._check("SAFE", None)
        self.assertEqual(out, {"facts": [], "disagrees": False})

    def test_allow_list_hit_is_a_fact(self):
        out = self._check("SAFE", None, is_allowlisted=True, list_reason="good.example")
        self.assertEqual([f["kind"] for f in out["facts"]], ["list"])
