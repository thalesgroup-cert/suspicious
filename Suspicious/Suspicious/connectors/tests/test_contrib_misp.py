from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.misp.connector import MISPConnector


class MISPConnectorTest(SimpleTestCase):
    def test_manifest(self):
        m = MISPConnector.manifest
        m.validate()
        self.assertEqual(m.name, "misp")
        self.assertIn("case_finalised", m.events)
        secret_keys = [f.key for f in m.config_schema if f.type == "secret"]
        self.assertIn("instances.primary.api_key", secret_keys)

    def test_health_check_unconfigured(self):
        with mock.patch(
            "settings.config.get_section", return_value={}
        ):
            status = MISPConnector({}).health_check()
        self.assertFalse(status.ok)

    def test_on_case_finalised_delegates_to_service(self):
        connector = MISPConnector({})
        fake_case = mock.Mock()
        with mock.patch(
            "connectors.contrib.misp.connector.MISPService"
        ) as service_cls, mock.patch(
            "connectors.contrib.misp.connector.Case"
        ) as case_model:
            case_model.objects.get.return_value = fake_case
            event = mock.Mock(case_id=7, status="Done")
            connector.on_case_finalised(event)
        service_cls.assert_called_once_with(primary=True)
        service_cls.return_value.update_misp.assert_called_once_with(fake_case)
