import dataclasses

from django.test import SimpleTestCase

from connectors.base import (
    CaseEvent,
    CatalogEntry,
    DATA_TYPE_MAIL_ARCHIVE,
    FETCH_GONE,
    FETCH_RESULT,
    FETCH_UNKNOWN,
    FetchResult,
    StartResult,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    Schedule,
    EVENT_CASE_CREATED,
    EVENT_CASE_FINALISED,
    url_errors,
)


def make_manifest(**overrides):
    kwargs = dict(name="dummy", version="1.0.0")
    kwargs.update(overrides)
    return ConnectorManifest(**kwargs)


class ManifestValidationTest(SimpleTestCase):
    def test_valid_manifest_passes(self):
        make_manifest(
            events=(EVENT_CASE_FINALISED,),
            schedules=(Schedule("sync", 300),),
            config_schema=(ConfigField("url", "url", required=True),),
        ).validate()

    def test_bad_slug_rejected(self):
        with self.assertRaises(ValueError):
            make_manifest(name="Bad Name!").validate()

    def test_unknown_event_rejected(self):
        with self.assertRaises(ValueError):
            make_manifest(events=("case_deleted",)).validate()

    def test_unknown_field_type_rejected(self):
        with self.assertRaises(ValueError):
            make_manifest(config_schema=(ConfigField("x", "float"),)).validate()

    def test_non_positive_schedule_rejected(self):
        with self.assertRaises(ValueError):
            make_manifest(schedules=(Schedule("sync", 0),)).validate()

    def test_case_created_event_valid(self):
        make_manifest(events=(EVENT_CASE_CREATED,)).validate()

    def test_case_modified_event_valid_and_routed_to_its_hook(self):
        from connectors.base import EVENT_CASE_MODIFIED
        from connectors.delivery import _HOOKS
        make_manifest(events=(EVENT_CASE_MODIFIED,)).validate()
        self.assertEqual(_HOOKS[EVENT_CASE_MODIFIED], "on_case_modified")

    def test_campaign_updated_event_valid_and_routed_to_its_hook(self):
        from connectors.base import EVENT_CAMPAIGN_UPDATED
        from connectors.delivery import _HOOKS
        make_manifest(events=(EVENT_CAMPAIGN_UPDATED,)).validate()
        self.assertEqual(_HOOKS[EVENT_CAMPAIGN_UPDATED], "on_campaign_updated")


class CaseEventRoundTripTest(SimpleTestCase):
    def test_to_dict_from_dict_round_trip(self):
        event = CaseEvent(
            schema_version=1, event="case_finalised", case_id=42,
            status="Done", results="Dangerous", final_score=9.5,
            confidence=80.0, reporter_email="a@b.c",
            created_at="2026-06-11T00:00:00+00:00",
        )
        self.assertEqual(CaseEvent.from_dict(event.to_dict()), event)

    def test_from_dict_rejects_unknown_schema_version(self):
        with self.assertRaises(ValueError):
            CaseEvent.from_dict({"schema_version": 99, "event": "x", "case_id": 1,
                                 "status": "", "results": "", "final_score": None,
                                 "confidence": None, "reporter_email": "",
                                 "created_at": ""})

    def test_schema_version_defaults_to_current(self):
        event = CaseEvent(
            event="case_created", case_id=1, status="", results="",
            final_score=None, confidence=None, reporter_email="", created_at="",
        )
        self.assertEqual(event.schema_version, 1)


class ConnectorABCTest(SimpleTestCase):
    def test_subclass_with_health_check_instantiable(self):
        class Dummy(Connector):
            manifest = make_manifest()
            def health_check(self):
                return HealthStatus(ok=True)
        d = Dummy({"url": "http://x"})
        self.assertEqual(d.config["url"], "http://x")
        self.assertTrue(d.health_check().ok)

    def test_direct_instantiation_rejected(self):
        with self.assertRaises(TypeError):
            Connector({})

    def test_subclass_without_health_check_rejected(self):
        class Bad(Connector):
            manifest = make_manifest()
        with self.assertRaises(TypeError):
            Bad({})


class UrlErrorsTest(SimpleTestCase):
    SCHEMA = (ConfigField("url", "url", required=True), ConfigField("extra.ui_url", "url"),
              ConfigField("name", "str"))

    def test_refused_urls_name_the_field_never_the_value(self):
        for value in ("file:///etc/passwd", "ftp://files.example/x", "javascript:alert(1)",
                      "http://user:pw@host", "https://token@host", "http://", "http:///path",
                      "ai_inference:8090", "http://host:99999", "  ", 8090, ["http://x"]):
            with self.subTest(value=value):
                errors = url_errors(self.SCHEMA, {"url": value})
                self.assertEqual(list(errors), ["url"])
                self.assertNotIn(str(value), errors["url"])
        self.assertEqual(list(url_errors(self.SCHEMA, {"url": "http://x", "extra": {"ui_url": "file:///x"}})),
                         ["extra.ui_url"])

    def test_valid_and_absent_urls_pass(self):
        for value in ("http://ai_inference:8090", "https://x/y", "HTTPS://Misp.example:8443/"):
            with self.subTest(value=value):
                self.assertEqual(url_errors(self.SCHEMA, {"url": value}), {})
        self.assertEqual(url_errors(self.SCHEMA, {}), {})
        self.assertEqual(url_errors(self.SCHEMA, {"url": None, "name": "file:///x"}), {})

    def test_an_empty_string_is_left_to_the_required_check(self):
        self.assertEqual(url_errors(self.SCHEMA, {"url": "http://x", "extra": {"ui_url": ""}}), {})


class EngineContractTest(SimpleTestCase):
    def test_types_frozen_and_value_equal(self):
        e = CatalogEntry("a", "A", ("mail",))
        self.assertEqual(e, CatalogEntry("a", "A", ("mail",)))
        r = FetchResult("result", "Success", {"a": 1}, {"b": 2})
        self.assertEqual((r.summary, r.full, r.status), ({"a": 1}, {"b": 2}, "Success"))
        self.assertEqual(r.data_type, "")
        self.assertEqual(FetchResult("result", "Success", None, None, data_type="file").data_type, "file")
        s = StartResult("j")
        self.assertIsNone(s.finished)
        for obj in (e, r, s):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                obj.__setattr__(dataclasses.fields(obj)[0].name, "x")

    def test_constants(self):
        self.assertEqual((FETCH_RESULT, FETCH_GONE, FETCH_UNKNOWN), ("result", "gone", "unknown"))

    def test_default_hooks_raise(self):
        class Bare(Connector):
            manifest = make_manifest()

            def health_check(self):
                return HealthStatus(True)

        b = Bare({})
        e = CatalogEntry("a", "A", ())
        for call in (lambda: b.catalog(), lambda: b.start(e, "mail", "v"),
                     lambda: b.fetch("j"), lambda: b.webhook({}, {})):
            with self.assertRaises(NotImplementedError):
                call()


class DeferredContractTest(SimpleTestCase):
    def test_constant_and_defaults(self):
        self.assertEqual(DATA_TYPE_MAIL_ARCHIVE, "mail_archive")
        self.assertFalse(StartResult("j").deferred)
        self.assertIsNone(FetchResult("result", "Success").payload)

    def test_default_hooks(self):
        class Bare(Connector):
            manifest = make_manifest()

            def health_check(self):
                return HealthStatus(ok=True)

        c = Bare({})
        self.assertIs(Bare.general_purpose, True)
        with self.assertRaises(NotImplementedError):
            c.run("j", "mail", "v")
        self.assertIsNone(c.on_started(object(), "a"))
        self.assertIsNone(c.on_result(object(), "a", FetchResult("result")))
