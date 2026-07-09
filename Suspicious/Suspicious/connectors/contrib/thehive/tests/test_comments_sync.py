from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, CaseComment
from connectors.contrib.thehive.comments import sync_case_comment_to_thehive


class SyncCaseCommentToTheHiveTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="sync_u", password="x", email="sync_u@example.com",
        )

    def _config_enabled(self):
        return {"enabled": True, "url": "https://stub", "api_key": "key"}

    def test_no_op_when_disabled(self):
        case = Case.objects.create(description="", reporter=self.user, thehive_alert_id="~alert-1")
        comment = CaseComment.objects.create(case=case, author=self.user, body="hi")

        with patch(
            "connectors.contrib.thehive.comments._thehive_config",
            return_value={"enabled": False},
        ), patch("connectors.contrib.thehive.comments.add_comment_to_item") as mock_comment:
            sync_case_comment_to_thehive(case, comment)

        mock_comment.assert_not_called()

    def test_no_op_when_no_alert_id(self):
        case = Case.objects.create(description="", reporter=self.user)
        comment = CaseComment.objects.create(case=case, author=self.user, body="hi")

        with patch(
            "connectors.contrib.thehive.comments._thehive_config",
            return_value=self._config_enabled(),
        ), patch("connectors.contrib.thehive.comments.add_comment_to_item") as mock_comment:
            sync_case_comment_to_thehive(case, comment)

        mock_comment.assert_not_called()

    def test_syncs_reporter_comment(self):
        case = Case.objects.create(description="", reporter=self.user, thehive_alert_id="~alert-2")
        comment = CaseComment.objects.create(case=case, author=self.user, body="please check", is_internal=False)

        with patch(
            "connectors.contrib.thehive.comments._thehive_config",
            return_value=self._config_enabled(),
        ), patch("connectors.contrib.thehive.comments.add_comment_to_item") as mock_comment:
            sync_case_comment_to_thehive(case, comment)

        mock_comment.assert_called_once_with(
            "alert", "~alert-2", {"message": "**sync_u@example.com**: please check"},
            "https://stub", "key",
        )

    def test_syncs_internal_comment_with_marker(self):
        case = Case.objects.create(description="", reporter=self.user, thehive_alert_id="~alert-3")
        comment = CaseComment.objects.create(case=case, author=self.user, body="looks clean", is_internal=True)

        with patch(
            "connectors.contrib.thehive.comments._thehive_config",
            return_value=self._config_enabled(),
        ), patch("connectors.contrib.thehive.comments.add_comment_to_item") as mock_comment:
            sync_case_comment_to_thehive(case, comment)

        mock_comment.assert_called_once_with(
            "alert", "~alert-3", {"message": "**sync_u@example.com** (internal): looks clean"},
            "https://stub", "key",
        )
