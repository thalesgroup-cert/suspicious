from django.test import SimpleTestCase

from connectors.base import FETCH_GONE, FetchResult, StartResult
from connectors.contrib.fixture.connector import FixtureEngineConnector

INERT = "fixture engine is inert: set confirm_fixture to true (never in production)"
ROLES = {
    "Fixture_Yara_1_0": ("file", "mail_body"),
    "Fixture_FileInfo_1_0": ("file",),
    "Fixture_Sandbox_1_0": ("file",),
    "Fixture_Header_1_0": ("mail_header",),
}


def make(**config):
    return FixtureEngineConnector(config)


class ManifestTest(SimpleTestCase):
    def test_manifest(self):
        m = FixtureEngineConnector.manifest
        self.assertEqual((m.name, m.provides, m.category), ("fixture_engine", "analysis", "Analysis"))
        self.assertIs(m.enabled_by_default, False)
        self.assertEqual([(f.key, f.type, f.default) for f in m.config_schema], [("confirm_fixture", "bool", False)])
        self.assertEqual(m.schedules, ())


class InertTest(SimpleTestCase):
    def assert_inert(self, connector):
        self.assertEqual(connector.catalog(), [])
        self.assertEqual(connector.catalog(data_type="url"), [])
        self.assertEqual(connector.catalog(name="Fixture_Yara_1_0"), [])
        health = connector.health_check()
        self.assertIs(health.ok, False)
        self.assertEqual(health.detail, INERT)
        entry = FixtureEngineConnector.CATALOG[0]
        self.assertIsNone(connector.start(entry, "url", "http://evil.example/"))

    def test_missing_and_non_true_values_are_inert(self):
        self.assert_inert(make())
        for value in ("true", 1, "True", None, False, [True]):
            with self.subTest(value=value):
                self.assert_inert(make(confirm_fixture=value))

    def test_config_read_at_call_time(self):
        connector = make(confirm_fixture=True)
        self.assertTrue(connector.catalog(data_type="url"))
        connector.config["confirm_fixture"] = "true"
        self.assert_inert(connector)
        connector.config["confirm_fixture"] = True
        self.assertTrue(connector.catalog(name="Fixture_Yara_1_0"))
        self.assertTrue(connector.health_check().ok)
        self.assertEqual(connector.health_check().detail, "fixture engine active (dev only)")
        del connector.config["confirm_fixture"]
        self.assert_inert(connector)


class InertLoggingTest(SimpleTestCase):
    def test_inert_catalog_warns_in_every_form(self):
        for kwargs in ({}, {"data_type": "url"}, {"name": "Fixture_Yara_1_0"}):
            with self.subTest(kwargs=kwargs), self.assertLogs("connectors.contrib.fixture.connector", "WARNING") as logs:
                make().catalog(**kwargs)
            self.assertEqual([r.getMessage() for r in logs.records], [INERT])

    def test_confirmed_catalog_logs_nothing(self):
        with self.assertNoLogs("connectors.contrib.fixture.connector"):
            make(confirm_fixture=True).catalog(data_type="url")


class ConfirmedTest(SimpleTestCase):
    def setUp(self):
        self.engine = make(confirm_fixture=True)

    def test_by_type_offers_only_the_reputation_analyzer(self):
        for data_type in ("url", "domain", "ip", "hash", "mail"):
            with self.subTest(data_type=data_type):
                self.assertEqual([e.name for e in self.engine.catalog(data_type=data_type)], ["Fixture_Reputation_1_0"])
        self.assertEqual(self.engine.catalog(data_type="file"), [])

    def test_by_name_offers_the_role_analyzers(self):
        for name, types in ROLES.items():
            with self.subTest(name=name):
                found = self.engine.catalog(name=name)
                self.assertEqual([(e.name, e.data_types) for e in found], [(name, types)])
        self.assertEqual(self.engine.catalog(name="Cortex_X"), [])

    def start(self, value, data_type="url"):
        return self.engine.start(self.engine.catalog(data_type="url")[0], data_type, value)

    def level(self, value):
        result = self.start(value)
        return result.finished.summary["taxonomies"][0]["level"]

    def test_verdicts(self):
        self.assertEqual(self.level("http://good.example/"), "safe")
        self.assertEqual(self.level("http://evil.example/"), "malicious")
        self.assertEqual(self.level("Phish.example"), "malicious")
        self.assertEqual(self.level("MALICIOUS.example"), "malicious")
        self.assertEqual(self.level("suspicious.example"), "suspicious")
        self.assertEqual(self.level("suspicious-evil.example"), "malicious")
        self.assertEqual(self.level("/tmp/evil/report.pdf"), "malicious")

    def test_empty_value_starts_nothing(self):
        for value in ("", "   ", None):
            self.assertIsNone(self.start(value))

    def test_result_shape(self):
        result = self.start("http://evil.example/", data_type="mail")
        self.assertIsInstance(result, StartResult)
        self.assertRegex(result.job_id, r"^fixture-[0-9a-f]{24}$")
        self.assertEqual(
            result.finished,
            FetchResult(
                "result", "Success",
                summary={"taxonomies": [{"level": "malicious", "namespace": "Fixture",
                                         "predicate": "Verdict", "value": "malicious"}]},
                full={"results": [{"threat": "malicious", "value": "http://evil.example/"}]},
                data_type="mail",
            ),
        )
        self.assertNotEqual(result.job_id, self.start("http://evil.example/").job_id)

    def test_fetch_is_gone_and_webhook_unimplemented(self):
        self.assertEqual(self.engine.fetch("fixture-x"), FetchResult(FETCH_GONE))
        with self.assertRaises(NotImplementedError):
            self.engine.webhook({}, {})
