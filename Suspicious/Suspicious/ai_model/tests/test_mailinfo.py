from unittest.mock import MagicMock

from django.test import SimpleTestCase

from ai_model.mailinfo import apply_mail_info
from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager


def _mail_info():
    return MagicMock(is_analyzed=False, is_phishing=False, is_dangerous=False)


class ApplyMailInfoTest(SimpleTestCase):
    def test_classic_phishing_sets_is_phishing(self):
        mail_info = _mail_info()
        apply_mail_info(mail_info, "Classic_phishing", "Dangerous")
        self.assertTrue(mail_info.is_phishing and mail_info.is_dangerous and mail_info.is_analyzed)
        mail_info.save.assert_called_once_with()

    def test_whaling_and_clone_set_is_phishing(self):
        for category in ("whaling", "CLONE"):
            mail_info = _mail_info()
            apply_mail_info(mail_info, category, "Suspicious")
            self.assertTrue(mail_info.is_phishing, category)
            self.assertFalse(mail_info.is_dangerous, category)

    def test_strips_and_lowercases(self):
        mail_info = _mail_info()
        apply_mail_info(mail_info, "  Whaling ", "  DANGEROUS ")
        self.assertTrue(mail_info.is_phishing and mail_info.is_dangerous)

    def test_other_category_only_marks_analyzed(self):
        mail_info = _mail_info()
        apply_mail_info(mail_info, "Uncategorized", "Safe")
        self.assertTrue(mail_info.is_analyzed)
        self.assertFalse(mail_info.is_phishing or mail_info.is_dangerous)

    def test_none_values_are_tolerated(self):
        mail_info = _mail_info()
        apply_mail_info(mail_info, None, None)
        self.assertTrue(mail_info.is_analyzed)
        self.assertFalse(mail_info.is_phishing or mail_info.is_dangerous)

    def test_no_mail_info_is_a_noop(self):
        apply_mail_info(None, "whaling", "Dangerous")

    def test_save_error_is_swallowed(self):
        mail_info = _mail_info()
        mail_info.save.side_effect = RuntimeError("db down")
        apply_mail_info(mail_info, "whaling", "Dangerous")

    def test_manager_method_delegates(self):
        mail_info = _mail_info()
        CortexJobManager.update_mail_models(CortexJobManager.__new__(CortexJobManager), mail_info, "clone", "Dangerous")
        self.assertTrue(mail_info.is_phishing and mail_info.is_dangerous and mail_info.is_analyzed)
