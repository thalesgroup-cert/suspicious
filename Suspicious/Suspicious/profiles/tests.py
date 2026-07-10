from django.test import TestCase
from unittest.mock import patch, MagicMock
from django.contrib.auth.models import User
import ldap as ldap_module

from profiles.models import CISOProfile, Theme, UserProfile
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
        self.assertEqual(profile.theme, Theme.LIGHT)


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
        self.assertEqual(profile.theme, Theme.LIGHT)


class CISOProcessingTests(TestCase):

    def setUp(self):
        self.user = User.objects.create(username="alice")

    @patch("profiles.profiles_utils.ciso.CISOProfile.objects.create")
    @patch("profiles.profiles_utils.ciso.search_ldap_server")
    @patch("profiles.profiles_utils.ciso.Ldap")
    def test_process_cisos_creates_ciso_profile(self, mock_ldap_class, mock_search, mock_create):
        mock_ldap_instance = MagicMock()
        mock_ldap_class.return_value.initialize_ldap.return_value = mock_ldap_instance

        mock_search.return_value = [
            (None, {
                "title": [b"CISO"],
                "businessCategory": [b"IT"],
                "c": [b"US"]
            })
        ]

        mock_create.return_value = MagicMock(spec=CISOProfile)

        good, error = process_cisos(["alice"])
        self.assertIn("alice", good)
        self.assertEqual(error, [])

    @patch("profiles.profiles_utils.ciso.Ldap")
    def test_process_cisos_user_does_not_exist(self, MockLdap):
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
        import io
        import json
        data = json.dumps([{"ciso": "alice"}, {"ciso": "bob"}]).encode("utf-8")
        file = io.BytesIO(data)
        result = handle_json_file(file)
        self.assertEqual(result, ["alice", "bob"])

    def test_handle_txt_file(self):
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

    @patch("profiles.profiles_utils.ldap.ldap.initialize")
    @patch("profiles.profiles_utils.ldap.ldap.set_option")
    @patch("profiles.profiles_utils.ldap._ldap_config", return_value={})
    def test_initialize_ldap_defaults_to_tls_demand(self, mock_config, mock_set_option, mock_initialize):
        Ldap().initialize_ldap()
        mock_set_option.assert_called_once_with(
            ldap_module.OPT_X_TLS_REQUIRE_CERT, ldap_module.OPT_X_TLS_DEMAND
        )

    @patch("profiles.profiles_utils.ldap.ldap.initialize")
    @patch("profiles.profiles_utils.ldap.ldap.set_option")
    @patch("profiles.profiles_utils.ldap._ldap_config", return_value={"verify_ssl": "false"})
    def test_initialize_ldap_verify_ssl_false_disables_tls(self, mock_config, mock_set_option, mock_initialize):
        Ldap().initialize_ldap()
        mock_set_option.assert_called_once_with(
            ldap_module.OPT_X_TLS_REQUIRE_CERT, ldap_module.OPT_X_TLS_NEVER
        )

    @patch("profiles.profiles_utils.ldap._ldap_config", return_value={"base_dn": "dc=meridian,dc=example"})
    def test_get_search_results_escapes_filter_chars(self, mock_config):
        mock_server = MagicMock()
        mock_server.search_s.return_value = []
        instance = MagicMock(username="x)(mail=*")

        Ldap.get_search_results(instance, mock_server)

        used_filter = mock_server.search_s.call_args[0][2]
        self.assertNotIn(")(mail=*)", used_filter)
        self.assertIn(r"\28mail=\2a", used_filter)

    def test_add_user_to_group_blocks_reserved_rbac_names(self):
        user = User.objects.create_user(username="sam.whitfield")
        Ldap.add_user_to_group(user, "Admin")
        self.assertEqual(user.groups.filter(name="Admin").count(), 0)

    def test_add_user_to_group_allows_non_reserved_names(self):
        user = User.objects.create_user(username="jordan.kim")
        Ldap.add_user_to_group(user, "Marketing")
        self.assertTrue(user.groups.filter(name="Marketing").exists())
