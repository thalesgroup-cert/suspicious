from django.test import SimpleTestCase

from connectors.contrib.thehive.utils import get_most_common_alert_id


def _campaign(*alert_id_fields):
    return {"metadatas": [[{"alert_ids": f} for f in alert_id_fields]]}


class MostCommonAlertIdTest(SimpleTestCase):
    def test_none_when_no_doc_has_an_alert(self):
        self.assertEqual(get_most_common_alert_id(_campaign('[""]', '[""]')), "")

    def test_alert_appended_after_the_initial_empty_entry_is_found(self):
        # a doc stored before any alert existed is [""], and the alert id is
        # appended to it when the campaign alert is created
        self.assertEqual(get_most_common_alert_id(_campaign('["", "~1"]', '["", "~1"]', '[""]')), "~1")

    def test_picks_the_most_frequent(self):
        self.assertEqual(get_most_common_alert_id(_campaign('["~2"]', '["~1"]', '["", "~1"]')), "~1")
