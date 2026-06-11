from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.watcher.connector import WatcherConnector


class WatcherConnectorTest(SimpleTestCase):
    def test_manifest_schedule(self):
        m = WatcherConnector.manifest
        m.validate()
        [schedule] = m.schedules
        self.assertEqual(schedule.interval_seconds, 300)

    def test_sync_delegates(self):
        with mock.patch(
            "connectors.contrib.watcher.sync.run_watcher_sync"
        ) as run_mock:
            WatcherConnector({}).sync()
        run_mock.assert_called_once_with()

    def test_health_check_unconfigured(self):
        self.assertFalse(WatcherConnector({}).health_check().ok)
