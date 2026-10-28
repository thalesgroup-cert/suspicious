from unittest.mock import MagicMock, patch

from django.test import RequestFactory, SimpleTestCase

from case_handler.case_utils.case_handler import CaseHandler


class HandleCaseWithoutArtifactTests(SimpleTestCase):
    """A submission that produced nothing must not leave an empty Case behind.

    Regression: a mail that failed to store (e.g. MariaDB "Got a packet bigger
    than 'max_allowed_packet' bytes") gave mail_instance=None, and handle_case
    still created a Case with no artifact: type unknown, 0 tests, and finally
    "Failure". The submit view now gets None and answers with an error.
    """

    def setUp(self):
        request = RequestFactory().post("/api/submit")
        request.user = MagicMock()
        invalid_forms = [MagicMock(**{"is_valid.return_value": False}) for _ in range(3)]
        self.handler = CaseHandler(request, *invalid_forms)

    @patch("case_handler.case_utils.case_handler.CaseCreator")
    def test_no_artifact_creates_no_case(self, creator):
        with self.assertLogs("case_handler.case_utils.case_handler", "ERROR"):
            self.assertIsNone(self.handler.handle_case())
        creator.assert_not_called()

    @patch("case_handler.case_utils.case_handler.CaseCreator")
    def test_allow_listed_flag_alone_is_not_a_case(self, creator):
        with self.assertLogs("case_handler.case_utils.case_handler", "ERROR"):
            self.assertIsNone(self.handler.handle_case(allow_listed=True, allow_reason="x"))
        creator.assert_not_called()

    @patch.object(CaseHandler, "_case_for_mail", return_value=None)
    @patch("case_handler.case_utils.case_handler.CaseCreator")
    def test_any_single_artifact_still_creates_a_case(self, creator, _no_mail_case):
        case = object()
        creator.return_value.create_case.return_value = case
        for kwarg in ("file_inst", "mail_inst", "ip_inst", "url_inst", "hash_inst"):
            with self.subTest(kwarg):
                self.assertIs(self.handler.handle_case(**{kwarg: MagicMock()}), case)
