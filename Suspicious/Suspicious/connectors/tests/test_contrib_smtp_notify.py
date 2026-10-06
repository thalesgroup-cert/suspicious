from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.smtp_notify.connector import SmtpNotifyConnector


class SmtpNotifyConnectorTest(SimpleTestCase):
    def test_manifest_enabled_by_default(self):
        m = SmtpNotifyConnector.manifest
        m.validate()
        self.assertTrue(m.enabled_by_default)
        self.assertIn("case_finalised", m.events)
        self.assertIn("case_created", m.events)
        self.assertIn("case_modified", m.events)

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
        fake_case.fileOrMail = mock.Mock(spec=[])
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


PATH = "connectors.contrib.smtp_notify.connector"


class AcknowledgementOnCaseCreatedTest(SimpleTestCase):
    def _run(self, *, case, mail_info=None, missing_info=False):
        connector = SmtpNotifyConnector({})
        with mock.patch(f"{PATH}.Case") as case_model, \
                mock.patch(f"{PATH}.MailInfo") as mail_info_model, \
                mock.patch(f"{PATH}.MailNotificationService") as svc:
            case_model.objects.select_related.return_value.get.return_value = case

            class _DoesNotExist(Exception):
                pass

            mail_info_model.DoesNotExist = _DoesNotExist
            if missing_info:
                mail_info_model.objects.get.side_effect = _DoesNotExist
            else:
                mail_info_model.objects.get.return_value = mail_info
            try:
                connector.on_case_created(mock.Mock(case_id=1))
            finally:
                self.svc = svc
        return svc

    def test_sends_acknowledgement_for_a_mail_case(self):
        case = mock.Mock()
        case.fileOrMail.mail = mock.Mock()
        info = mock.Mock()
        svc = self._run(case=case, mail_info=info)
        svc.from_settings.return_value.send_acknowledgement.assert_called_once_with(info)

    def test_skips_cases_without_a_mail(self):
        case = mock.Mock()
        case.fileOrMail = None
        svc = self._run(case=case)
        svc.from_settings.return_value.send_acknowledgement.assert_not_called()

    def test_retries_when_mailinfo_is_not_written_yet(self):
        # the case is created a moment before ingest records MailInfo
        case = mock.Mock()
        case.fileOrMail.mail = mock.Mock()
        with self.assertRaises(RuntimeError):
            self._run(case=case, missing_info=True)
        self.svc.from_settings.return_value.send_acknowledgement.assert_not_called()


class ReviewOnCaseModifiedTest(SimpleTestCase):
    def test_sends_review_email(self):
        connector = SmtpNotifyConnector({})
        case = mock.Mock()
        with mock.patch(f"{PATH}.Case") as case_model, \
                mock.patch(f"{PATH}.MailNotificationService") as svc:
            case_model.objects.get.return_value = case
            connector.on_case_modified(mock.Mock(case_id=1))
        svc.from_settings.return_value.send_review_email.assert_called_once_with(case)

    def test_deleted_case_is_skipped(self):
        connector = SmtpNotifyConnector({})
        with mock.patch(f"{PATH}.Case") as case_model, \
                mock.patch(f"{PATH}.MailNotificationService") as svc:
            case_model.DoesNotExist = type("DoesNotExist", (Exception,), {})
            case_model.objects.get.side_effect = case_model.DoesNotExist
            connector.on_case_modified(mock.Mock(case_id=1))
        svc.from_settings.return_value.send_review_email.assert_not_called()
