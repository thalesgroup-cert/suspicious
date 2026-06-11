from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.smtp_notify.connector import SmtpNotifyConnector


class SmtpNotifyConnectorTest(SimpleTestCase):
    def test_manifest_enabled_by_default(self):
        m = SmtpNotifyConnector.manifest
        m.validate()
        self.assertTrue(m.enabled_by_default)
        self.assertIn("case_finalised", m.events)

    def test_skips_non_done_cases(self):
        connector = SmtpNotifyConnector({})
        with mock.patch(
            "connectors.contrib.smtp_notify.connector.MailNotificationService"
        ) as svc:
            connector.on_case_finalised(mock.Mock(status="Ongoing", case_id=1))
        svc.from_settings.assert_not_called()

    def test_sends_final_for_done_mail_case(self):
        connector = SmtpNotifyConnector({})
        fake_mail = mock.Mock()
        fake_mail_info = mock.Mock()
        fake_case = mock.Mock()
        fake_case.fileOrMail.mail = fake_mail
        with mock.patch(
            "connectors.contrib.smtp_notify.connector.Case"
        ) as case_model, mock.patch(
            "connectors.contrib.smtp_notify.connector.MailInfo"
        ) as mail_info_model, mock.patch(
            "connectors.contrib.smtp_notify.connector.MailNotificationService"
        ) as svc:
            case_model.objects.select_related.return_value.get.return_value = fake_case
            mail_info_model.objects.get.return_value = fake_mail_info
            connector.on_case_finalised(mock.Mock(status="Done", case_id=1))
        svc.from_settings.return_value.send_final.assert_called_once_with(
            fake_mail_info, fake_case
        )

    def test_skips_ioc_only_case(self):
        connector = SmtpNotifyConnector({})
        fake_case = mock.Mock()
        fake_case.fileOrMail = None
        with mock.patch(
            "connectors.contrib.smtp_notify.connector.Case"
        ) as case_model, mock.patch(
            "connectors.contrib.smtp_notify.connector.MailNotificationService"
        ) as svc:
            case_model.objects.select_related.return_value.get.return_value = fake_case
            connector.on_case_finalised(mock.Mock(status="Done", case_id=1))
        svc.from_settings.return_value.send_final.assert_not_called()

    def test_skips_file_only_case(self):
        connector = SmtpNotifyConnector({})
        fake_case = mock.Mock()
        fake_case.fileOrMail = mock.Mock(spec=[])  # no .mail attribute
        with mock.patch(
            "connectors.contrib.smtp_notify.connector.Case"
        ) as case_model, mock.patch(
            "connectors.contrib.smtp_notify.connector.MailNotificationService"
        ) as svc:
            case_model.objects.select_related.return_value.get.return_value = fake_case
            connector.on_case_finalised(mock.Mock(status="Done", case_id=1))
        svc.from_settings.return_value.send_final.assert_not_called()

    def test_skips_when_mailinfo_missing(self):
        connector = SmtpNotifyConnector({})
        fake_case = mock.Mock()
        fake_case.fileOrMail.mail = mock.Mock()
        with mock.patch(
            "connectors.contrib.smtp_notify.connector.Case"
        ) as case_model, mock.patch(
            "connectors.contrib.smtp_notify.connector.MailInfo"
        ) as mail_info_model, mock.patch(
            "connectors.contrib.smtp_notify.connector.MailNotificationService"
        ) as svc:
            case_model.objects.select_related.return_value.get.return_value = fake_case
            class _DoesNotExist(Exception):
                pass
            mail_info_model.DoesNotExist = _DoesNotExist
            mail_info_model.objects.get.side_effect = _DoesNotExist
            connector.on_case_finalised(mock.Mock(status="Done", case_id=1))
        svc.from_settings.return_value.send_final.assert_not_called()
