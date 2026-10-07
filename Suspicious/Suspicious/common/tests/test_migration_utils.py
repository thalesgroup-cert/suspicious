from unittest import mock

from django.apps import apps
from django.contrib.auth.models import Group
from django.test import TestCase

from common.migration_utils import refuse_if_rows


class RefuseIfRowsTests(TestCase):
    def _run(self):
        op = refuse_if_rows("auth", "Group")
        editor = mock.Mock()
        editor.connection.alias = "default"
        op.code(apps, editor)

    def test_empty_table_passes(self):
        Group.objects.all().delete()
        self._run()

    def test_rows_abort_the_migration(self):
        Group.objects.create(name="keep-me")
        with self.assertRaisesMessage(RuntimeError, "Refusing to drop auth.Group"):
            self._run()

    def test_reverse_is_a_noop(self):
        self.assertIs(refuse_if_rows("auth", "Group").reverse_code, refuse_if_rows("auth", "Group").reverse_code)
