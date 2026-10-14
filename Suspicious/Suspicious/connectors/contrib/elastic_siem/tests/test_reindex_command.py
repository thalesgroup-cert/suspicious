from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from case_handler.models import Case
from connectors.contrib.elastic_siem import service

CONFIG = {"url": "https://siem.corp:9200", "api_key": "KEY123", "index": "idx"}
CMD = "connectors.management.commands.reindex_siem"


class ReindexSiemTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", "alice@x.io", "pw")
        for results in ("Dangerous", "Suspicious", "Inconclusive", "Safe", "Failure"):
            Case.objects.create(description=results, reporter=cls.user, results=results)

    def _run(self, *args, config=None, enabled=True, client=None, **kwargs):
        client = client or mock.Mock()
        client.bulk.side_effect = lambda docs: (len(docs), 0)
        out = StringIO()
        with mock.patch(f"{CMD}.get_section", return_value=CONFIG if config is None else config), \
             mock.patch(f"{CMD}.get_state", return_value=mock.Mock(enabled=enabled)), \
             mock.patch.object(service, "SiemClient", return_value=client):
            call_command("reindex_siem", *args, stdout=out, **kwargs)
        return client, out.getvalue()

    def test_sends_only_cases_at_or_above_min_verdict(self):
        client, out = self._run()
        sent_ids = [case_id for call in client.bulk.call_args_list for case_id, _ in call[0][0]]
        verdicts = sorted(Case.objects.get(pk=i).results for i in sent_ids)
        self.assertEqual(verdicts, ["Dangerous", "Suspicious"])
        client.ensure_index.assert_called_once_with()
        self.assertIn("2 sent", out)
        self.assertIn("3 skipped", out)
        self.assertIn("0 failed", out)

    def test_documents_are_tagged_reindex(self):
        client, _ = self._run()
        doc = client.bulk.call_args[0][0][0][1]
        self.assertEqual(doc["event"]["action"], "reindex")

    def test_min_verdict_option_overrides_config(self):
        client, out = self._run(min_verdict="Safe")
        self.assertIn("4 sent", out)  # Failure has no rank
        client, out = self._run(min_verdict="Dangerous")
        self.assertIn("1 sent", out)

    def test_since_filters_by_last_update(self):
        client, out = self._run(since="2999-01-01")
        self.assertIn("0 sent", out)
        client.bulk.assert_not_called()

    def test_invalid_since_raises(self):
        with self.assertRaises(CommandError):
            self._run(since="not-a-date")

    def test_dry_run_sends_nothing(self):
        client, out = self._run(dry_run=True)
        client.ensure_index.assert_not_called()
        client.bulk.assert_not_called()
        self.assertIn("2 would be sent", out)

    def test_batches_of_500(self):
        with mock.patch(f"{CMD}.BATCH_SIZE", 1):
            client, out = self._run()
        self.assertEqual(client.bulk.call_count, 2)

    def test_refuses_when_disabled(self):
        with self.assertRaises(CommandError):
            self._run(enabled=False)

    def test_refuses_when_unconfigured(self):
        with self.assertRaises(CommandError):
            self._run(config={})

    def test_unknown_min_verdict_raises(self):
        with self.assertRaises(CommandError):
            self._run(min_verdict="Banana")

    def test_failed_documents_make_the_command_fail(self):
        client = mock.Mock()
        client.bulk.side_effect = lambda docs: (len(docs) - 1, 1)
        out = StringIO()
        with mock.patch(f"{CMD}.get_section", return_value=CONFIG), \
             mock.patch(f"{CMD}.get_state", return_value=mock.Mock(enabled=True)), \
             mock.patch.object(service, "SiemClient", return_value=client):
            with self.assertRaises(CommandError):
                call_command("reindex_siem", stdout=out)
