from datetime import timedelta
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Case
from connectors.contrib.case_search import service


class ReindexCommandTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", "a@x.io", "pw")
        cls.old = Case.objects.create(description="old", reporter=cls.user)
        cls.new = Case.objects.create(description="new", reporter=cls.user)
        Case.objects.filter(pk=cls.old.pk).update(last_update=timezone.now() - timedelta(days=30))

    def _run(self, *args):
        out = StringIO()
        with mock.patch.object(service, "get_client") as gc, \
                mock.patch.object(service, "bulk_index", return_value=(2, 0)) as bulk:
            gc.return_value.indices.exists.return_value = True
            call_command("reindex_cases", *args, stdout=out)
        return bulk, out.getvalue()

    def test_indexes_all_cases(self):
        bulk, out = self._run()
        cases = list(bulk.call_args.args[2])
        self.assertEqual({c.pk for c in cases}, {self.old.pk, self.new.pk})
        self.assertIn("2 indexed", out)

    def test_since_limits_to_recently_updated(self):
        since = (timezone.now() - timedelta(days=1)).date().isoformat()
        bulk, _ = self._run("--since", since)
        self.assertEqual({c.pk for c in bulk.call_args.args[2]}, {self.new.pk})

    def test_bad_date_is_a_command_error(self):
        from django.core.management.base import CommandError

        with self.assertRaises(CommandError):
            call_command("reindex_cases", "--since", "not-a-date")
