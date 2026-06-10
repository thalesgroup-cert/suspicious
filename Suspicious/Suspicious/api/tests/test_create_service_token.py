from io import StringIO
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase

User = get_user_model()


class CreateServiceTokenTest(TestCase):
    def test_creates_user_group_and_prints_token(self):
        out = StringIO()
        call_command("create_service_token", "feeder", stdout=out)
        user = User.objects.get(username="svc-feeder")
        self.assertTrue(user.groups.filter(name="feeder").exists())
        self.assertTrue(user.is_active and not user.is_staff)
        self.assertTrue(len(out.getvalue().strip()) >= 40)

    def test_idempotent_user(self):
        call_command("create_service_token", "feeder", stdout=StringIO())
        call_command("create_service_token", "feeder", stdout=StringIO())
        self.assertEqual(User.objects.filter(username="svc-feeder").count(), 1)

    def test_rejects_unknown_scope(self):
        from django.core.management.base import CommandError
        with self.assertRaises(CommandError):
            call_command("create_service_token", "nope", stdout=StringIO())

    def test_rejects_shared_scope(self):
        from django.core.management.base import CommandError
        with self.assertRaises(CommandError):
            call_command("create_service_token", "shared", stdout=StringIO())

    def test_token_has_no_expiry(self):
        from knox.models import AuthToken
        call_command("create_service_token", "feeder", stdout=StringIO())
        tok = AuthToken.objects.filter(user__username="svc-feeder").latest("created")
        self.assertIsNone(tok.expiry)
