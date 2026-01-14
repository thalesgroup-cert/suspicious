from django.test import TestCase
from unittest.mock import patch, MagicMock
from django.contrib.auth.models import User

from profiles.models import CISOProfile, UserProfile
from profiles.profiles_utils.ciso import process_cisos, generate_message, handle_csv_file, handle_json_file, handle_txt_file
from profiles.profiles_utils.ldap import Ldap

class UserProfileModelTests(TestCase):

    def test_str_representation(self):
        user = User.objects.create(username="alice")
        profile = UserProfile.objects.create(user=user, function="Dev", gbu="IT", country="US", region="NORAM")
        self.assertEqual(str(profile), "alice")

    def test_default_fields(self):
        user = User.objects.create(username="bob")
        profile = UserProfile.objects.create(user=user, function="Dev", gbu="IT", country="US", region="NORAM")
        self.assertTrue(profile.wants_acknowledgement)
        self.assertTrue(profile.wants_results)
        self.assertEqual(profile.theme, "default")


class CISOProfileModelTests(TestCase):

    def test_str_representation(self):
        user = User.objects.create(username="ciso1")
        profile = CISOProfile.objects.create(user=user, function="CISO", gbu="IT", country="US", region="NORAM")
        self.assertEqual(str(profile), "ciso1")

    def test_default_fields(self):
        user = User.objects.create(username="ciso2")
        profile = CISOProfile.objects.create(user=user, function="CISO", gbu="IT", country="US", region="NORAM")
        self.assertTrue(profile.wants_acknowledgement)
        self.assertTrue(profile.wants_results)
        self.assertEqual(profile.theme, "default")


class CISOProcessingTests(TestCase):

    def setUp(self):
        self.user = User.objects.create(username="alice")

    @patch("profiles.profiles_utils.ciso.CISOProfile.objects.create")
    @patch("profiles.profiles_utils.ciso.search_ldap_server")
    @patch("profiles.profiles_utils.ciso.Ldap")
    def test_process_cisos_creates_ciso_profile(self, mock_ldap_class, mock_search, mock_create):
        # Mock LDAP server
        mock_ldap_instance = MagicMock()
        mock_ldap_class.return_value.initialize_ldap.return_value = mock_ldap_instance

        # Mock LDAP search results with bytes
        mock_search.return_value = [
            (None, {
                "title": [b"CISO"],
                "businessCategory": [b"IT"],
                "c": [b"US"]
            })
        ]

        # Mock CISOProfile creation
        mock_create.return_value = MagicMock(spec=CISOProfile)

        good, error = process_cisos(["alice"])
        self.assertIn("alice", good)
        self.assertEqual(error, [])

    @patch("profiles.profiles_utils.ciso.Ldap")
    def test_process_cisos_user_does_not_exist(self, MockLdap):
        # Mock LDAP initialization
        mock_ldap = MockLdap.return_value
        mock_ldap.initialize_ldap.return_value = MagicMock()

        good, error = process_cisos(["nonexistent"])

        self.assertEqual(good, [])
        self.assertEqual(error, ["nonexistent"])

    def test_generate_message(self):
        msg = generate_message(["alice", "bob"], ["carol"], 5)
        self.assertIn("2 CISO profiles added", msg)
        self.assertIn("1 CISO profiles not added", msg)

    def test_handle_csv_file(self):
        import io
        file = io.BytesIO(b"ciso\nalice\nbob\n")
        result = handle_csv_file(file)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["ciso"], "alice")

    def test_handle_json_file(self):
        import io, json
        data = json.dumps([{"ciso": "alice"}, {"ciso": "bob"}]).encode("utf-8")
        file = io.BytesIO(data)
        result = handle_json_file(file)
        self.assertEqual(result, ["alice", "bob"])

    def test_handle_txt_file(self):
        import io
        file = [b"alice\n", b"bob\n"]
        result = handle_txt_file(file)
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
