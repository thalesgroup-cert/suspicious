from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from ai_model.models import AiAssessment, LabelRecord
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
        self.assertEqual(out["reads"], "body text only, not headers or attachments")

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

    def test_similar_case_is_projected_to_the_contract_keys(self):
        mine = Case.objects.create(description="", reporter=self.user)
        self._assess(similar_cases=[{"case_id": mine.pk, "similarity": 0.8, "excerpt": "mail text"}])
        self.assertEqual(
            self._present()["similar_cases"],
            [{"case_id": mine.pk, "similarity": 0.8, "label": None, "provenance": None}],
        )

    def test_similar_case_with_a_non_integer_id_is_dropped(self):
        mine = Case.objects.create(description="", reporter=self.user)
        bad = [{"case_id": str(mine.pk)}, {"case_id": True}, {"case_id": None}, {}, "x"]
        self._assess(similar_cases=[*bad, {"case_id": mine.pk}])
        self.assertEqual([e["case_id"] for e in self._present()["similar_cases"]], [mine.pk])

    def test_runner_up_skips_non_numeric_probabilities(self):
        self._assess(
            tier="low",
            probabilities={"DANGEROUS": 0.5, "SAFE": "high", "UNWANTED": None, "X": 0.1},
        )
        self.assertEqual(self._present()["runner_up"], {"result": "X"})

    def test_runner_up_is_none_when_no_probability_is_usable(self):
        self._assess(tier="low", probabilities={"DANGEROUS": 0.5, "SAFE": "high", "UNWANTED": [1]})
        self.assertIsNone(self._present()["runner_up"])

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

    def test_campaign_size_without_prefetch_only_counts(self):
        campaign = Campaign.objects.create()
        CampaignMember.objects.create(campaign=campaign, case=self.case)
        other = Case.objects.create(description="", reporter=self.other)
        CampaignMember.objects.create(campaign=campaign, case=other)
        case = Case.objects.select_related("campaign_membership__campaign").get(pk=self.case.pk)
        with CaptureQueriesContext(connection) as ctx:
            self.assertEqual(_campaign(case), {"ref": campaign.ref, "size": 2})
        self.assertEqual(len(ctx.captured_queries), 1)
        self.assertIn("COUNT(", ctx.captured_queries[0]["sql"].upper())

    def test_blank_model_version_gives_none(self):
        self._assess(model_version="")
        self.assertIsNone(self._present())

    def test_unknown_tier_is_shown_as_not_calibrated(self):
        for tier in ("HIGH", "certain", "None"):
            with self.subTest(tier):
                AiAssessment.objects.filter(case=self.case).delete()
                self._assess(tier=tier)
                self.assertEqual(self._present()["tier"], "")

    def test_cross_check_is_null_for_a_non_elevated_viewer(self):
        self._assess()
        self.assertIsNone(present_assessment(Case.objects.get(pk=self.case.pk), self.user)["cross_check"])

    def test_cross_check_is_present_for_an_analyst(self):
        from django.contrib.auth.models import Group
        analyst = get_user_model().objects.create_user(username="cert", password="pass")
        analyst.groups.add(Group.objects.get_or_create(name="CERT")[0])
        self._assess()
        out = present_assessment(Case.objects.get(pk=self.case.pk), analyst)
        self.assertEqual(out["cross_check"], {"facts": [], "disagrees": False})

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

    def test_ai_decisive_rule_is_not_listed_and_never_disagrees(self):
        out = self._check("SAFE", {"decisive_rule": "ai-classifier-decisive", "band": "Dangerous"})
        self.assertEqual(
            out, {"facts": [{"kind": "rule", "text": "No independent evidence beyond the AI"}],
                  "disagrees": False},
        )

    def test_no_explanation_compares_with_the_case_verdict(self):
        out = self._check("SAFE", None, results="Dangerous")  # e.g. an analyst override
        self.assertEqual(out, {"facts": [], "disagrees": True})
        self.assertFalse(self._check("DANGEROUS", None, results="Dangerous")["disagrees"])

    def test_malformed_explanation_is_tolerated(self):
        for bad in ("text", ["a"], 3):
            with self.subTest(bad):
                self.assertEqual(self._check("SAFE", bad), {"facts": [], "disagrees": False})
        out = self._check("SAFE", {"sources": ["x", None, {"name": "n", "verdict": "v", "counted": True}]})
        self.assertEqual([f["kind"] for f in out["facts"]], ["source"])
        self.assertEqual(self._check("SAFE", {"sources": "oops"}), {"facts": [], "disagrees": False})

    def test_allow_list_hit_is_a_fact(self):
        out = self._check("SAFE", None, is_allowlisted=True, list_reason="good.example")
        self.assertEqual([f["kind"] for f in out["facts"]], ["list"])


class CampaignLabelsTest(TestCase):
    """Sibling folder labels on the campaign line, for elevated viewers only."""

    def setUp(self):
        from django.contrib.auth.models import Group
        users = get_user_model().objects
        self.reporter = users.create_user(username="r", password="pass")
        self.analyst = users.create_user(username="cert", password="pass")
        self.analyst.groups.add(Group.objects.get_or_create(name="CERT")[0])
        self.case = Case.objects.create(description="", reporter=self.reporter)
        self.campaign = Campaign.objects.create()
        CampaignMember.objects.create(campaign=self.campaign, case=self.case)
        AiAssessment.objects.create(
            case=self.case, model_version="v0", result="DANGEROUS", score=9, confidence=90
        )

    def _sibling(self, *labels, status="active", source="imap_folder", trust="folder"):
        sibling = Case.objects.create(description="", reporter=self.reporter)
        CampaignMember.objects.create(campaign=self.campaign, case=sibling)
        for n, label_class in enumerate(labels):
            LabelRecord.objects.create(
                message_id=f"m{sibling.pk}.{n}", message_id_hash=f"h{sibling.pk}.{n}", case=sibling,
                source=source, label="x", label_class=label_class, trust=trust, status=status,
            )
        return sibling

    def _campaign_for(self, user):
        case = Case.objects.select_related("ai_assessment", "campaign_membership__campaign").get(
            pk=self.case.pk
        )
        return present_assessment(case, user)["campaign"]

    def test_labels_count_active_folder_rows_of_the_siblings(self):
        for _ in range(3):
            self._sibling("Dangerous")
        self._sibling("Safe")
        out = self._campaign_for(self.analyst)
        self.assertEqual(out["labels"], {"Dangerous": 3, "Safe": 1})
        self.assertEqual(out["size"], 5)

    def test_this_case_flagged_superseded_and_non_folder_rows_do_not_count(self):
        LabelRecord.objects.create(
            message_id="own", message_id_hash="own", case=self.case, source="imap_folder",
            label="x", label_class="Safe", trust="folder",
        )
        self._sibling("Safe", status="flagged")
        self._sibling("Safe", status="superseded")
        self._sibling("Safe", source="analyst_verdict", trust="verdict")
        self._sibling("Safe", source="challenge", trust="proposal")
        self.assertEqual(
            self._campaign_for(self.analyst),
            {"ref": self.campaign.ref, "size": 5, "labels": {}, "members_disagree": False},
        )

    def test_no_labelled_sibling_gives_empty_labels_and_no_disagreement(self):
        self._sibling()
        out = self._campaign_for(self.analyst)
        self.assertEqual((out["labels"], out["members_disagree"]), ({}, False))

    def test_siblings_with_dangerous_and_safe_disagree(self):
        AiAssessment.objects.filter(case=self.case).update(result="UNWANTED")
        self._sibling("Dangerous")
        self._sibling("Safe")
        self.assertTrue(self._campaign_for(self.analyst)["members_disagree"])

    def test_dangerous_ai_against_a_safe_sibling_disagrees(self):
        self._sibling("Safe")
        self.assertTrue(self._campaign_for(self.analyst)["members_disagree"])

    def test_safe_ai_against_a_dangerous_sibling_disagrees(self):
        AiAssessment.objects.filter(case=self.case).update(result="Safe")
        self._sibling("Dangerous")
        self.assertTrue(self._campaign_for(self.analyst)["members_disagree"])

    def test_same_side_and_unwanted_do_not_disagree(self):
        self._sibling("Dangerous")
        self._sibling("Unwanted")
        out = self._campaign_for(self.analyst)
        self.assertEqual(out["labels"], {"Dangerous": 1, "Unwanted": 1})
        self.assertFalse(out["members_disagree"])
        LabelRecord.objects.filter(label_class="Dangerous").delete()
        AiAssessment.objects.filter(case=self.case).update(result="UNWANTED")
        self._sibling("Safe")
        self.assertFalse(self._campaign_for(self.analyst)["members_disagree"])

    def test_reporter_sees_ref_and_size_only(self):
        self._sibling("Dangerous")
        self.assertEqual(
            self._campaign_for(self.reporter), {"ref": self.campaign.ref, "size": 2}
        )

    def test_labels_of_all_siblings_take_one_query(self):
        for label_class in ("Dangerous", "Safe", "Dangerous", "Unwanted"):
            self._sibling(label_class)
        case = (
            Case.objects.select_related("ai_assessment")
            .prefetch_related("campaign_membership__campaign__members")
            .get(pk=self.case.pk)
        )
        with self.assertNumQueries(1):
            out = _campaign(case, case.ai_assessment, elevated=True)
        self.assertEqual(out["labels"], {"Dangerous": 2, "Unwanted": 1, "Safe": 1})
