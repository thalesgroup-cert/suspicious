from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase

from case_handler.models import Campaign, CampaignMember, Case


def _case():
    user, _ = get_user_model().objects.get_or_create(username="rep", defaults={"email": "r@e.c"})
    return Case.objects.create(reporter=user, description="t")


class CampaignModelTest(TestCase):
    def test_ref_is_generated_and_unique(self):
        a, b = Campaign.objects.create(title="a"), Campaign.objects.create(title="b")
        self.assertTrue(a.ref.startswith("CAMP-"))
        self.assertNotEqual(a.ref, b.ref)

    def test_external_refs_and_synced_default_empty(self):
        campaign = Campaign.objects.create(title="a")
        member = CampaignMember.objects.create(campaign=campaign, case=_case())
        self.assertEqual(campaign.external_refs, {})
        self.assertEqual(member.synced, [])

    def test_a_case_belongs_to_one_campaign(self):
        case = _case()
        CampaignMember.objects.create(campaign=Campaign.objects.create(title="a"), case=case)
        with self.assertRaises(IntegrityError), transaction.atomic():
            CampaignMember.objects.create(campaign=Campaign.objects.create(title="b"), case=case)

    def test_membership_is_reachable_from_the_case(self):
        case = _case()
        campaign = Campaign.objects.create(title="a")
        CampaignMember.objects.create(campaign=campaign, case=case)
        self.assertEqual(case.campaign_membership.campaign, campaign)
