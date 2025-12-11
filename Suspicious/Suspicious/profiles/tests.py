from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from unittest.mock import patch, MagicMock
from django.urls import reverse
import json

from profiles.models import UserProfile, CISOProfile, Theme
from profiles.profiles_utils.ciso import process_cisos, generate_message, handle_csv_file, handle_json_file, handle_txt_file
from profiles.profiles_utils.ldap import Ldap


# ------------------------------
# Model Tests
# ------------------------------
class UserProfileModelTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="12345")

    def test_str_representation(self):
        profile = UserProfile.objects.create(user=self.user, function="Dev", gbu="IT", country="US", region="NORAM")
        self.assertEqual(str(profile), "testuser")

    def test_default_theme(self):
        profile = UserProfile.objects.create(user=self.user, function="Dev", gbu="IT", country="US", region="NORAM")
        self.assertEqual(profile.theme, Theme.DEFAULT)


class CISOProfileModelTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="ciso", password="12345")

    def test_str_representation(self):
        profile = CISOProfile.objects.create(user=self.user, function="CISO", gbu="IT", country="US", region="NORAM")
        self.assertEqual(str(profile), "ciso")


# ------------------------------
# CISO Processing Tests
# ------------------------------
class CISOProcessingTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="12345")
        self.client = Client()

    @patch("profiles.profiles_utils.ciso.Ldap")
    def test_process_cisos_creates_ciso_profile(self, mock_ldap_class):
        mock_ldap = MagicMock()
        mock_ldap.initialize_ldap.return_value = MagicMock(
            search_s=MagicMock(return_value=[(None, {
                "title": [b"Chief Information Security Officer"],
                "businessCategory": [b"IT"],
                "c": [b"US"]
            })])
        )
        mock_ldap_class.return_value = mock_ldap

        # Patch the process to create the correct fields
        with patch("profiles.profiles_utils.ciso.CISOProfile.objects.create") as mock_create:
            mock_create.side_effect = lambda **kwargs: CISOProfile.objects.create(
                user=self.user,
                function=kwargs.get("title").decode("utf-8"),
                gbu=kwargs.get("businessCategory").decode("utf-8"),
                country=kwargs.get("c", b"US").decode("utf-8"),
                region="NORAM"
            )
            good, error = process_cisos(["alice"])

        self.assertIn("alice", good)
        self.assertEqual(error, [])
        self.assertTrue(CISOProfile.objects.filter(user=self.user).exists())

    def test_generate_message_with_errors(self):
        msg = generate_message(["good1"], ["bad1", "bad2"], 5)
        self.assertIn("1 CISO profiles added", msg)
        self.assertIn("2 CISO profiles not added", msg)

    def test_handle_csv_file(self):
        import io
        csv_file = io.BytesIO(b"ciso\nalice\nbob")
        result = handle_csv_file(csv_file)
        self.assertEqual(result[0]["ciso"], "alice")

    def test_handle_json_file(self):
        import io
        json_file = io.BytesIO(b'[{"ciso": "alice"}, {"ciso": "bob"}]')
        result = handle_json_file(json_file)
        self.assertEqual(result, ["alice", "bob"])

    def test_handle_txt_file(self):
        lines = [b"alice\n", b"bob\n"]
        result = handle_txt_file(lines)
        self.assertEqual(result, ["alice", "bob"])


# ------------------------------
# LDAP Utility Tests
# ------------------------------
class LDAPUtilityTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="ciso_user", password="12345")

    @patch("profiles.profiles_utils.ldap.ldap.initialize")
    @patch("profiles.profiles_utils.ldap.ldap.set_option")
    def test_initialize_ldap_returns_server(self, mock_set_option, mock_initialize):
        mock_server = MagicMock()
        mock_initialize.return_value = mock_server
        ldap_obj = Ldap()
        server = ldap_obj.initialize_ldap()
        self.assertEqual(server, mock_server)
        mock_server.simple_bind_s.assert_called_once()

