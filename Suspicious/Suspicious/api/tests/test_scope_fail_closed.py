"""scoped_case_queryset: a CISO-group member with no CISOProfile has no scope
to apply, so they see nothing. CERT/Admin and non-CISO users are unchanged."""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.models import Case
from profiles.models import CISOProfile
from profiles.profiles_utils.scope import scoped_case_queryset

User = get_user_model()


def _user(username, groups=()):
    user = User.objects.create_user(username=username, password="pw-12345")
    for name in groups:
        group, _ = Group.objects.get_or_create(name=name)
        user.groups.add(group)
    return user


class ScopedCaseQuerysetFailClosedTests(TestCase):
    def setUp(self):
        reporter = _user("sc_reporter", groups=["EMEA"])
        self.case = Case.objects.create(reporter=reporter, description="c")

    def _ids(self, user):
        return set(scoped_case_queryset(Case.objects.all(), user).values_list("id", flat=True))

    def test_ciso_group_without_profile_sees_nothing(self):
        user = _user("sc_ciso_noprofile", groups=["CISO"])
        self.assertFalse(CISOProfile.objects.filter(user=user).exists())
        self.assertEqual(self._ids(user), set())

    def test_ciso_group_without_profile_sees_nothing_on_investigation_list(self):
        user = _user("sc_ciso_noprofile_api", groups=["CISO"])
        client = APIClient()
        client.force_authenticate(user)
        resp = client.get(reverse("investigation-list"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual({row["id"] for row in resp.data["results"]}, set())

    def test_cert_and_admin_are_unchanged(self):
        for group in ("CERT", "Admin"):
            with self.subTest(group=group):
                self.assertEqual(self._ids(_user(f"sc_{group}", groups=[group])), {self.case.id})

    def test_cert_and_ciso_without_profile_is_still_unrestricted(self):
        user = _user("sc_cert_ciso", groups=["CERT", "CISO"])
        self.assertEqual(self._ids(user), {self.case.id})

    def test_non_ciso_user_is_unchanged(self):
        self.assertEqual(self._ids(_user("sc_plain")), {self.case.id})

    def test_ciso_with_all_scope_still_sees_everything(self):
        user = _user("sc_ciso_all")
        CISOProfile.objects.create(user=user, scope="ALL")
        self.assertEqual(self._ids(user), {self.case.id})

    def test_ciso_with_unset_scope_still_sees_nothing(self):
        user = _user("sc_ciso_unset")
        CISOProfile.objects.create(user=user)  # scope defaults to "Not defined"
        self.assertEqual(self._ids(user), set())
