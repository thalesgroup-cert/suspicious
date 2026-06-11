from django.test import SimpleTestCase

from connectors.base import (
    CaseEvent,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    Schedule,
    EVENT_CASE_FINALISED,
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


class CaseEventRoundTripTest(SimpleTestCase):
    def test_to_dict_from_dict_round_trip(self):
        event = CaseEvent(
            schema_version=1, event="case_finalised", case_id=42,
            status="Done", results="Dangerous", final_score=9.5,
            confidence=80.0, reporter_email="a@b.c",
            created_at="2026-06-11T00:00:00+00:00",
        )
        self.assertEqual(CaseEvent.from_dict(event.to_dict()), event)


class ConnectorABCTest(SimpleTestCase):
    def test_subclass_with_health_check_instantiable(self):
        class Dummy(Connector):
            manifest = make_manifest()
            def health_check(self):
                return HealthStatus(ok=True)
        d = Dummy({"url": "http://x"})
        self.assertEqual(d.config["url"], "http://x")
        self.assertTrue(d.health_check().ok)
