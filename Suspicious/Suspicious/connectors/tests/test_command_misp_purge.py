from io import StringIO
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase

from connectors.management.commands import misp_purge_company_iocs as cmd

_EVENT = {"Event": {"id": "7", "info": "MalSpam cases - October 2026", "Attribute": [], "Object": [
    {"id": "1", "name": "email", "Attribute": [
        {"id": "10", "type": "email-dst", "value": "jane@corp.example", "object_relation": "to"},
        {"id": "11", "type": "email-dst", "value": "jane@corp.example, p@ext.test", "object_relation": "cc"},
    ]},
    {"id": "2", "name": "url", "Attribute": [
        {"id": "20", "type": "url", "value": "https://corp.example/x", "object_relation": "url"},
    ]},
]}}


class PurgeCommandTest(SimpleTestCase):
    def _run(self, *args, domains=frozenset({"corp.example"})):
        misp = MagicMock()
        misp.search.return_value = [{"Event": {"id": "7", "info": "MalSpam cases - October 2026"}}]
        misp.get_event.return_value = _EVENT
        out = StringIO()
        with patch.object(cmd, "MISPClient", return_value=MagicMock(misp=misp)), \
                patch.object(cmd, "load_misp_settings"), \
                patch.object(cmd, "company_domains", return_value=domains), \
                patch.object(cmd, "current_month_event_name", return_value="MalSpam cases - October 2026"):
            call_command(cmd.Command(), *args, stdout=out)
        return misp, out.getvalue()

    def test_dry_run_lists_and_writes_nothing(self):
        misp, out = self._run()
        self.assertIn("3 finding(s)", out)
        self.assertIn("dry run", out)
        misp.delete_object.assert_not_called()
        misp.delete_attribute.assert_not_called()
        misp.update_attribute.assert_not_called()

    def test_apply_deletes_rewrites_and_removes_objects(self):
        misp, out = self._run("--apply")
        misp.delete_attribute.assert_called_once_with("10")
        misp.update_attribute.assert_called_once_with({"value": "p@ext.test"}, attribute_id="11")
        misp.delete_object.assert_called_once_with("2")
        self.assertIn("applied 3 change(s), failed 0", out)

    def test_empty_company_domains_refuse_to_run(self):
        with self.assertRaises(CommandError):
            self._run(domains=frozenset())
