import hashlib
from dataclasses import FrozenInstanceError

from django.test import TestCase

from ai_model.campaign_profile import allow_list_digest, current_profile
from ai_model.models import AiAssessment
from domain_process.models import Domain
from settings.models import CampaignDomainAllowList


def _allow(*values):
    for value in values:
        CampaignDomainAllowList.objects.create(domain=Domain.objects.create(value=value))


class CampaignProfileTest(TestCase):
    def test_profile_values_match_the_spec_table(self):
        profile = current_profile()
        self.assertEqual(profile.embedding_version, "cmp-e1")
        self.assertEqual(profile.collection_name, "suspicious_mails")
        self.assertEqual(profile.max_tokens, 128)
        self.assertEqual(profile.distance_threshold, 0.25)
        self.assertEqual(profile.min_members, 3)
        self.assertEqual(profile.neighbours, 20)
        self.assertEqual(profile.window_days, 15)
        self.assertEqual(profile.trigger_class, "DANGEROUS")
        self.assertEqual(profile.trigger_class, AiAssessment.Result.DANGEROUS)
        self.assertEqual(profile.allow_list_digest, allow_list_digest())
        with self.assertRaises(FrozenInstanceError):
            profile.min_members = 2

    def test_digest_ignores_order_and_changes_with_the_list(self):
        _allow("b.example", "a.example")
        first = allow_list_digest()
        self.assertEqual(
            first, hashlib.sha256(b"a.example\nb.example").hexdigest()[:16]
        )
        CampaignDomainAllowList.objects.all().delete()
        Domain.objects.all().delete()
        _allow("a.example", "b.example")
        self.assertEqual(allow_list_digest(), first)
        _allow("c.example")
        self.assertNotEqual(allow_list_digest(), first)
        self.assertEqual(current_profile().allow_list_digest, allow_list_digest())

    def test_empty_allow_list_has_a_defined_digest(self):
        self.assertEqual(allow_list_digest(), hashlib.sha256(b"").hexdigest()[:16])

    def test_rows_without_a_domain_are_ignored(self):
        CampaignDomainAllowList.objects.create(domain=None)
        self.assertEqual(allow_list_digest(), hashlib.sha256(b"").hexdigest()[:16])
