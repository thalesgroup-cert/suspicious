from unittest import mock

from django.test import TestCase

from ai_model import registry, serversync, tasks
from ai_model.models import ModelVersion
from ai_model.tests.test_registry import cand
from common.storage.fake import FakeObjectStore
from connectors.contrib.ai_model.client import ServerBusy
from connectors.providers import ProviderUnavailable


def meta(active="v0", shadow=None):
    out = {"name": "ai_mail", "versions": {"active": {"id": active}}}
    if shadow:
        out["versions"]["shadow"] = {"id": shadow}
    return out


class SyncTest(TestCase):
    def setUp(self):
        p = mock.patch.object(registry, "get_store", return_value=FakeObjectStore())
        p.start()
        self.addCleanup(p.stop)
        self.client = mock.Mock()

    def go(self, active="v1", shadow="v2"):
        a = registry.set_active(cand(active)) if active else registry.ensure_version_zero()
        if shadow:
            registry.set_shadow(cand(shadow, manifest={"eligible": True}))
        return a

    def test_wanted_state_follows_the_registry(self):
        self.go()
        state = serversync.wanted_state()
        self.assertEqual((state["active"]["version_id"], state["shadow"]["version_id"]), ("v1", "v2"))

    def test_version_zero_active_sends_null(self):
        registry.ensure_version_zero()
        self.assertEqual(serversync.wanted_state(), {"active": None, "shadow": None})

    def test_server_matches_compares_ids(self):
        self.go()
        self.client.metadata.return_value = meta("v1", "v2")
        self.assertTrue(serversync.server_matches(self.client))
        for bad in (meta("v1"), meta("v0", "v2"), meta("v1", "v9")):
            self.client.metadata.return_value = bad
            self.assertFalse(serversync.server_matches(self.client))

    def test_version_zero_matches_the_legacy_server(self):
        registry.ensure_version_zero()
        self.client.metadata.return_value = meta("v0")
        self.assertTrue(serversync.server_matches(self.client))

    def test_no_reload_when_matching(self):
        self.go()
        self.client.metadata.return_value = meta("v1", "v2")
        self.assertTrue(serversync.sync(self.client))
        self.client.reload.assert_not_called()

    def test_reload_on_mismatch_and_a_fresh_server_gets_the_state(self):
        self.go()
        self.client.metadata.side_effect = [meta("v0"), meta("v1", "v2")]
        self.assertTrue(serversync.sync(self.client))
        self.client.reload.assert_called_once()
        self.assertEqual(self.client.reload.call_args.args[0]["active"]["version_id"], "v1")

    def test_still_differing_after_reload_is_false(self):
        self.go()
        self.client.metadata.return_value = meta("v0")
        self.assertFalse(serversync.sync(self.client))

    def test_refused_reload_raises_without_url_or_body(self):
        self.go()
        self.client.metadata.return_value = meta("v0")
        self.client.reload.side_effect = ValueError("inference server refused the request (HTTP 422)")
        with self.assertRaises(serversync.ReloadRefused) as ctx:
            serversync.sync(self.client)
        self.assertNotIn("fake://", str(ctx.exception))
        self.assertNotIn("http", str(ctx.exception).lower())

    def test_a_refused_shadow_is_retried_without_it_and_leaves_one_event(self):
        self.go()
        shadow = ModelVersion.objects.get(version_id="v2")
        self.client.metadata.return_value = meta("v0")
        for _ in range(2):  # the beat's next run: same refusal, no second event
            self.client.reload.reset_mock()
            self.client.reload.side_effect = [ValueError("inference server refused the request (HTTP 422)"), {}]
            with self.assertLogs("ai_model.serversync", "WARNING") as logs:
                self.assertFalse(serversync.sync(self.client))  # the server still lacks the shadow
            bodies = [c.args[0] for c in self.client.reload.call_args_list]
            self.assertEqual([b["shadow"] is None for b in bodies], [False, True])
            self.assertEqual(bodies[1]["active"]["version_id"], "v1")
            self.assertNotIn("422", "".join(logs.output))
        self.assertEqual(list(shadow.events.filter(action="shadow_refused").values_list("user", flat=True)), [None])
        shadow.refresh_from_db()
        self.assertEqual(shadow.status, ModelVersion.Status.SHADOW)

    def test_shadow_must_load_raises_shadow_refused_after_the_retry(self):
        self.go()
        self.client.metadata.return_value = meta("v0")
        self.client.reload.side_effect = [ValueError("HTTP 422"), {}]
        with self.assertRaises(serversync.ShadowRefused):
            serversync.sync(self.client, shadow_must_load=True)
        self.assertEqual(self.client.reload.call_count, 2)

    def test_refused_with_and_without_the_shadow_is_reload_refused(self):
        self.go()
        self.client.metadata.return_value = meta("v0")
        self.client.reload.side_effect = ValueError("HTTP 422")
        with self.assertRaises(serversync.ReloadRefused) as ctx:
            serversync.sync(self.client)
        self.assertNotIsInstance(ctx.exception, serversync.ShadowRefused)
        self.assertEqual(self.client.reload.call_count, 2)
        self.assertFalse(ModelVersion.objects.filter(events__action="shadow_refused").exists())

    def test_without_a_shadow_a_refusal_is_not_retried(self):
        self.go(shadow=None)
        self.client.metadata.return_value = meta("v0")
        self.client.reload.side_effect = ValueError("HTTP 422")
        with self.assertRaises(serversync.ReloadRefused):
            serversync.sync(self.client)
        self.assertEqual(self.client.reload.call_count, 1)

    def test_an_unconfigured_connector_is_a_transient_failure(self):
        self.go()
        for exc in (ValueError("token secret"), KeyError("ai_model")):
            with mock.patch("connectors.registry.registry.instantiate") as inst, \
                    self.assertLogs("ai_model.serversync", "WARNING") as logs:
                inst.return_value._client.side_effect = exc
                self.assertFalse(serversync.sync())
            self.assertIn(type(exc).__name__, logs.output[0])
            self.assertNotIn("secret", logs.output[0])

    def test_a_4xx_on_the_metadata_get_is_not_a_refused_reload(self):
        self.go()
        self.client.metadata.side_effect = ValueError("inference server refused the request (HTTP 422)")
        with self.assertLogs("ai_model.serversync", "WARNING") as logs:
            self.assertFalse(serversync.sync(self.client))
        self.assertIn("ValueError", logs.output[0])
        self.assertNotIn("422", logs.output[0])
        self.client.reload.assert_not_called()

    def test_the_beat_task_logs_a_refusal_by_class_only(self):
        with mock.patch("ai_model.ledger.enabled", return_value=True), \
                mock.patch("connectors.registry.registry.instantiate"), \
                mock.patch.object(serversync, "sync", side_effect=serversync.ReloadRefused("x")), \
                self.assertLogs("ai_model.tasks", "WARNING") as logs:
            tasks.sync_server()  # does not raise
        self.assertIn("ReloadRefused", logs.output[0])
        self.assertIsNone(logs.records[0].exc_info)

    def test_unavailable_and_busy_return_false_and_log_the_class(self):
        self.go()
        self.client.metadata.return_value = meta("v0")
        for exc in (ProviderUnavailable("x secret"), ServerBusy("y")):
            self.client.reload.side_effect = exc
            with self.assertLogs("ai_model.serversync", "WARNING") as logs:
                self.assertFalse(serversync.sync(self.client))
            self.assertIn(type(exc).__name__, logs.output[0])
            self.assertNotIn("secret", logs.output[0])

    def test_task_is_a_noop_when_disabled_or_unconfigured(self):
        with mock.patch("ai_model.ledger.enabled", return_value=False), \
                mock.patch.object(serversync, "sync") as sync:
            tasks.sync_server()
        sync.assert_not_called()
        with mock.patch("ai_model.ledger.enabled", return_value=True), \
                mock.patch("connectors.registry.registry.instantiate") as inst, \
                mock.patch.object(serversync, "sync") as sync:
            inst.return_value._client.side_effect = ValueError("token not configured")
            tasks.sync_server()
        sync.assert_not_called()

    def test_task_syncs_when_enabled(self):
        with mock.patch("ai_model.ledger.enabled", return_value=True), \
                mock.patch("connectors.registry.registry.instantiate") as inst, \
                mock.patch.object(serversync, "sync") as sync:
            tasks.sync_server()
        sync.assert_called_once_with(inst.return_value._client.return_value)

    def test_beat_entry(self):
        from suspicious.celery import app
        entry = app.conf.beat_schedule["ai-model-server-sync"]
        self.assertEqual((entry["task"], entry["schedule"]), ("ai_model.tasks.sync_server", 300.0))
