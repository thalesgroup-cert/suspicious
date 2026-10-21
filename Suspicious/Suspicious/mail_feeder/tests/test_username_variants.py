from django.contrib.auth import get_user_model
from django.test import TestCase

from mail_feeder.minio_submission.minio import _get_user_by_username_variants
from domain_process.models import Domain
from settings.models import WatcherLegitDomain


class UsernameVariantsTests(TestCase):
    def setUp(self):
        WatcherLegitDomain.objects.create(domain=Domain.objects.create(value="corp.example"))
        self.user = get_user_model().objects.create_user(
            username="theo.bhang", email="theo.bhang@corp.example", password="x"
        )

    def test_dotted_username_matches(self):
        self.assertEqual(_get_user_by_username_variants("theo.bhang"), self.user)

    def test_bucket_normalised_username_matches_dotted_email(self):
        # bucket names turn "." (and "_") into "-"
        self.assertEqual(_get_user_by_username_variants("theo-bhang"), self.user)
