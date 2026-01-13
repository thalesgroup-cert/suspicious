from django.test import TestCase
from django.contrib.auth import get_user_model
from unittest.mock import patch, MagicMock
from io import BytesIO
from domain_process.models import Domain
from hash_process.models import Hash
from .models import (
    Mailbox,
    EmailFeederState,
    AllowListDomain,
    DenyListDomain,
    CampaignDomainAllowList,
    AllowListFile,
    DenyListFile,
    AllowListFiletype,
)

from settings.settings_utils.feeder_email import (
    check_if_feeder_is_running,
    enable_email_feeder,
    disable_email_feeder,
)

from settings.settings_utils.filetype import (
    validate_value,
    validate_filetype,
    process_filetypes,
    generate_filetype_message,
    handle_filetype_csv_file,
    handle_filetype_json_file,
    handle_filetype_txt_file,
)

from settings.settings_utils.domain import (
    handle_domain_file,
    handle_bdomain_file,
    handle_campaign_domain_file,
    process_domains,
    process_bdomains,
    process_campaign_domains,
    generate_message_domain,
    preprocess_domains,
    handle_domain_csv_file,
    handle_domain_json_file,
    handle_domain_txt_file,
    INVALID_FILETYPE_ERROR,
)

User = get_user_model()

class MailboxModelTests(TestCase):

    def test_password_is_hashed_on_save(self):
        mailbox = Mailbox.objects.create(
            name="Inbox",
            username="inbox",
            password="cleartext",
            server="mail.example.com",
            port=993,
        )

        self.assertNotEqual(mailbox.password, "cleartext")
        self.assertTrue(mailbox.password.startswith("pbkdf2_"))

    def test_str_representation(self):
        mailbox = Mailbox.objects.create(
            name="MainMailbox",
            username="main",
            password="secret",
            server="mail.example.com",
            port=993,
        )
        self.assertEqual(str(mailbox), "MainMailbox")

class EmailFeederStateModelTests(TestCase):

    def test_str_running(self):
        state = EmailFeederState.objects.create(is_running=True)
        self.assertEqual(str(state), "Email Feeder is ON")

    def test_str_stopped(self):
        state = EmailFeederState.objects.create(is_running=False)
        self.assertEqual(str(state), "Email Feeder is OFF")

class DomainListModelTests(TestCase):

    def setUp(self):
        self.user = User.objects.create(username="alice")
        self.domain = Domain.objects.create(value="example.com")

    def test_allow_list_domain_str(self):
        obj = AllowListDomain.objects.create(user=self.user, domain=self.domain)
        self.assertEqual(str(obj), "example.com")

    def test_deny_list_domain_str(self):
        obj = DenyListDomain.objects.create(user=self.user, domain=self.domain)
        self.assertEqual(str(obj), "example.com")

    def test_campaign_allow_list_domain_str(self):
        obj = CampaignDomainAllowList.objects.create(user=self.user, domain=self.domain)
        self.assertEqual(str(obj), "example.com")

class FileListModelTests(TestCase):

    def setUp(self):
        self.user = User.objects.create(username="bob")
        self.hash = Hash.objects.create(value="abcd1234")

    def test_allow_list_file_str(self):
        obj = AllowListFile.objects.create(
            user=self.user,
            linked_file_hash=self.hash,
        )
        self.assertEqual(str(obj), "abcd1234")

    def test_deny_list_file_str(self):
        obj = DenyListFile.objects.create(
            user=self.user,
            linked_file_hash=self.hash,
        )
        self.assertEqual(str(obj), "abcd1234")

class AllowListFiletypeTests(TestCase):

    def test_str_representation(self):
        user = User.objects.create(username="charlie")
        obj = AllowListFiletype.objects.create(
            user=user,
            filetype="pdf",
        )
        self.assertEqual(str(obj), "pdf")

class FeederEmailTests(TestCase):

    @patch("settings.settings_utils.feeder_email.docker_client")
    def test_check_feeder_running(self, mock_docker):
        container = MagicMock()
        container.status = "running"
        mock_docker.containers.get.return_value = container

        self.assertTrue(check_if_feeder_is_running())

    @patch("settings.settings_utils.feeder_email.docker_client")
    def test_check_feeder_not_running(self, mock_docker):
        container = MagicMock()
        container.status = "exited"
        mock_docker.containers.get.return_value = container

        self.assertFalse(check_if_feeder_is_running())

    @patch("settings.settings_utils.feeder_email.docker_client")
    def test_check_feeder_not_found(self, mock_docker):
        mock_docker.containers.get.side_effect = Exception()
        self.assertFalse(check_if_feeder_is_running())

    @patch("settings.settings_utils.feeder_email.check_if_feeder_is_running")
    def test_enable_feeder_already_running(self, mock_check):
        mock_check.return_value = True
        self.assertTrue(enable_email_feeder())

    @patch("settings.settings_utils.feeder_email.docker_client")
    @patch("settings.settings_utils.feeder_email.check_if_feeder_is_running")
    def test_enable_feeder_starts_container(self, mock_check, mock_docker):
        mock_check.side_effect = [False, True]
        container = MagicMock()
        mock_docker.containers.get.return_value = container

        self.assertTrue(enable_email_feeder())
        container.start.assert_called_once()

    @patch("settings.settings_utils.feeder_email.check_if_feeder_is_running")
    def test_disable_feeder_already_stopped(self, mock_check):
        mock_check.return_value = False
        self.assertTrue(disable_email_feeder())

    @patch("settings.settings_utils.feeder_email.docker_client")
    @patch("settings.settings_utils.feeder_email.check_if_feeder_is_running")
    def test_disable_feeder_stops_container(self, mock_check, mock_docker):
        mock_check.side_effect = [True, False]
        container = MagicMock()
        mock_docker.containers.get.return_value = container

        self.assertTrue(disable_email_feeder())
        container.stop.assert_called_once()

class FiletypeValidationTests(TestCase):

    def test_validate_value_valid(self):
        result = validate_value("pdf", {"Filetype": r"^[a-z]{1,10}$"})
        self.assertEqual(result, "Filetype")

    def test_validate_value_invalid(self):
        result = validate_value("pdf.exe", {"Filetype": r"^[a-z]{1,10}$"})
        self.assertIsNone(result)

    def test_validate_filetype_valid(self):
        self.assertEqual(validate_filetype("exe"), "Filetype")

    def test_validate_filetype_invalid(self):
        self.assertIsNone(validate_filetype("exe!!!"))

class ProcessFiletypesTests(TestCase):

    def setUp(self):
        self.user = User.objects.create(username="alice")

    def test_process_filetypes_creates_new(self):
        good, error = process_filetypes(["PDF", "exe"], self.user)

        self.assertEqual(sorted(good), ["exe", "pdf"])
        self.assertEqual(error, [])
        self.assertEqual(AllowListFiletype.objects.count(), 2)

    def test_process_filetypes_existing_goes_to_error(self):
        AllowListFiletype.objects.create(filetype="pdf", user=self.user)

        good, error = process_filetypes(["pdf"], self.user)

        self.assertEqual(good, [])
        self.assertEqual(error, ["pdf"])
        self.assertEqual(AllowListFiletype.objects.count(), 1)

    def test_process_filetypes_invalid_ignored(self):
        good, error = process_filetypes(["pdf", "exe!!"], self.user)

        self.assertEqual(good, ["pdf"])
        self.assertEqual(error, [])
        self.assertEqual(AllowListFiletype.objects.count(), 1)

class FiletypeMessageTests(TestCase):

    def test_generate_message_no_errors(self):
        msg = generate_filetype_message(["pdf", "exe"], [], 1)

        self.assertEqual(
            msg,
            "2 filetypes added to the database. 1 filetypes already in the database."
        )

    def test_generate_message_with_errors(self):
        msg = generate_filetype_message(["pdf"], ["exe"], 2)

        self.assertEqual(
            msg,
            "1 filetypes added to the database. 2 filetypes already in the database. "
            "1 filetypes not added to the database: exe."
        )

class FiletypeFileHandlersTests(TestCase):

    def test_handle_csv_file(self):
        content = b"pdf\nexe\ndocx\n"
        file = BytesIO(content)

        result = handle_filetype_csv_file(file)
        self.assertEqual(result, ["pdf", "exe", "docx"])

    def test_handle_json_file(self):
        content = b'[{"filetype": "pdf"}, {"filetype": "exe"}]'
        file = BytesIO(content)

        result = handle_filetype_json_file(file)
        self.assertEqual(result, ["pdf", "exe"])

    def test_handle_txt_file(self):
        content = [b"pdf\n", b"exe\n"]
        result = handle_filetype_txt_file(content)

        self.assertEqual(result, ["pdf", "exe"])

class DomainFileDispatchTests(TestCase):

    def test_handle_domain_file_csv(self):
        file = MagicMock()
        file.content_type = "text/csv"
        file.read.return_value = b"domain\nexample.com\n"

        result = handle_domain_file(file)
        self.assertEqual(result[0]["domain"], "example.com")

    def test_handle_domain_file_invalid_type(self):
        file = MagicMock()
        file.content_type = "application/xml"

        with self.assertRaises(ValueError) as ctx:
            handle_domain_file(file)

        self.assertEqual(str(ctx.exception), INVALID_FILETYPE_ERROR)

class DomainFileHandlersTests(TestCase):

    def test_handle_domain_csv_file(self):
        content = b"domain\nexample.com\ntest.com\n"
        file = BytesIO(content)

        result = handle_domain_csv_file(file)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["domain"], "example.com")

    def test_handle_domain_json_file(self):
        content = b'[{"domain": "example.com"}, {"domain": "test.com"}]'
        file = BytesIO(content)

        result = handle_domain_json_file(file)
        self.assertEqual(result, ["example.com", "test.com"])

    def test_handle_domain_txt_file(self):
        content = [b"example.com\n", b"test.com\n"]

        result = handle_domain_txt_file(content)
        self.assertEqual(result, ["example.com", "test.com"])

class PreprocessDomainsTests(TestCase):

    def test_preprocess_string_domains(self):
        domains = ["example.com, test.com", " foo.com "]

        result = preprocess_domains(domains)
        self.assertEqual(result, ["example.com", "test.com", "foo.com"])

    def test_preprocess_dict_domains(self):
        domains = [{"domain__value": "example.com test.com"}]

        result = preprocess_domains(domains)
        self.assertEqual(result, ["example.com", "test.com"])

class ProcessDomainsTests(TestCase):

    def setUp(self):
        self.user = User.objects.create(username="alice")

    @patch("settings.settings_utils.domain.DomainHandler.validate_domain")
    def test_process_domains_creates_new(self, mock_validate):
        mock_validate.return_value = "Domain"

        good, error = process_domains(["Example.com"], self.user)

        self.assertEqual(good, ["example.com"])
        self.assertEqual(error, [])
        self.assertEqual(AllowListDomain.objects.count(), 1)
        self.assertEqual(Domain.objects.count(), 1)

    @patch("settings.settings_utils.domain.DomainHandler.validate_domain")
    def test_process_domains_existing_goes_to_error(self, mock_validate):
        mock_validate.return_value = "Domain"

        domain = Domain.objects.create(value="example.com")
        AllowListDomain.objects.create(domain=domain, user=self.user)

        good, error = process_domains(["example.com"], self.user)

        self.assertEqual(good, [])
        self.assertEqual(error, ["example.com"])

class ProcessBDomainsTests(TestCase):

    def setUp(self):
        self.user = User.objects.create(username="bob")

    @patch("settings.settings_utils.domain.DomainHandler.validate_domain")
    def test_process_bdomains_creates_new(self, mock_validate):
        mock_validate.return_value = "Domain"

        good, error = process_bdomains(["bad.com"], self.user)

        self.assertEqual(good, ["bad.com"])
        self.assertEqual(error, [])
        self.assertEqual(DenyListDomain.objects.count(), 1)

class ProcessCampaignDomainsTests(TestCase):

    def setUp(self):
        self.user = User.objects.create(username="charlie")

    @patch("settings.settings_utils.domain.DomainHandler.validate_domain")
    def test_process_campaign_domains_creates_new(self, mock_validate):
        mock_validate.return_value = "Domain"

        good, error = process_campaign_domains(["campaign.com"], self.user)

        self.assertEqual(good, ["campaign.com"])
        self.assertEqual(error, [])
        self.assertEqual(CampaignDomainAllowList.objects.count(), 1)

class DomainMessageTests(TestCase):

    def test_generate_message_without_errors(self):
        msg = generate_message_domain(
            user="alice",
            good_domains=["a.com", "b.com"],
            error_domains=[],
            count=1,
        )

        self.assertEqual(
            msg,
            "User : alice - 2 domains added to the database. 1 domains already in the database."
        )

    def test_generate_message_with_errors(self):
        msg = generate_message_domain(
            user="alice",
            good_domains=["a.com"],
            error_domains=["b.com"],
            count=2,
        )

        self.assertEqual(
            msg,
            "User : alice - 1 domains added to the database. 2 domains already in the database. "
            "1 domains not added to the database: b.com."
        )

