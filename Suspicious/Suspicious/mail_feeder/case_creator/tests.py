from django.test import TestCase
from unittest.mock import patch, MagicMock
from django.contrib.auth.models import User

from mail_feeder.case_creator.creator import CaseCreatorService
from mail_feeder.case_creator.models import CaseInputData


class CaseCreatorServiceTests(TestCase):

    def setUp(self):
        self.service = CaseCreatorService()
        self.user = User(username="alice")
        self.mail_instance = MagicMock()

    def _input_data(self):
        return CaseInputData(
            instance=self.mail_instance,
            user=self.user,
            artifact_ids=["a1", "a2"],
            attachment_ids=["f1"]
        )

    def test_merge_ids(self):
        data = self._input_data()
        self.service._merge_ids(data)
        self.assertEqual(data.list_ids, ["a1", "a2", "f1"])

    def test_prepare_case_dict(self):
        result = self.service._prepare_case_dict(self.mail_instance)
        self.assertEqual(result["mail_instance"], self.mail_instance)
        self.assertIsNone(result["file_instance"])
        self.assertIsNone(result["ip_instance"])
        self.assertIsNone(result["url_instance"])
        self.assertIsNone(result["hash_instance"])

    @patch("mail_feeder.case_creator.creator.CaseCreator")
    @patch("mail_feeder.case_creator.creator.UserCreationService.get_or_create_user")
    def test_create_case_success(self, mock_get_user, mock_case_creator):
        data = self._input_data()

        user_instance = MagicMock()
        mock_get_user.return_value = user_instance

        case_instance = MagicMock()
        case_instance.fileOrMail = MagicMock()

        mock_case_creator.return_value.create_case.return_value = case_instance

        result = self.service.create_case(data)

        self.assertEqual(result, case_instance)
        case_instance.save.assert_called_once()
        self.assertEqual(case_instance.fileOrMail.mail, self.mail_instance)

    @patch("mail_feeder.case_creator.creator.CaseCreator")
    @patch("mail_feeder.case_creator.creator.UserCreationService.get_or_create_user")
    def test_create_case_returns_none(self, mock_get_user, mock_case_creator):
        data = self._input_data()

        mock_get_user.return_value = MagicMock()
        mock_case_creator.return_value.create_case.return_value = None

        result = self.service.create_case(data)

        self.assertIsNone(result)

    @patch("mail_feeder.case_creator.creator.CaseCreator")
    @patch("mail_feeder.case_creator.creator.UserCreationService.get_or_create_user")
    def test_create_case_exception_propagates(self, mock_get_user, mock_case_creator):
        data = self._input_data()

        mock_get_user.return_value = MagicMock()
        mock_case_creator.return_value.create_case.side_effect = Exception("boom")

        with self.assertRaises(Exception):
            self.service.create_case(data)
