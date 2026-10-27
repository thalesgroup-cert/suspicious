from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase

from connectors.dispatch import emit


class EmitExcludeTest(TestCase):
    def test_excluded_subscribers_are_not_delivered_to(self):
        case = SimpleNamespace(id=1)
        with patch("connectors.dispatch.build_case_event") as build, \
             patch("connectors.dispatch.registry.subscribers", return_value=["smtp_notify", "case_search"]), \
             patch("connectors.delivery.get_state", return_value=SimpleNamespace(enabled=True)), \
             patch("connectors.tasks.deliver_event.apply_async") as deliver, \
             self.captureOnCommitCallbacks(execute=True):
            build.return_value.to_dict.return_value = {}
            emit("case_modified", case, exclude=("smtp_notify",))
        self.assertEqual([c.args[0][0] for c in deliver.call_args_list], ["case_search"])
