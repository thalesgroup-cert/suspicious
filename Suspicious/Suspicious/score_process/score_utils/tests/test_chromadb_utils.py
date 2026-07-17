from unittest.mock import MagicMock

from django.test import TestCase

from score_process.score_utils.chromadb_utils import get_similar_dangerous_mails


class GetSimilarDangerousMailsTest(TestCase):
    """P6 regression: n_results must be a parameter (default 20),
    not a hard-coded 70."""

    def _make_collection(self):
        coll = MagicMock()
        coll.query.return_value = {}
        return coll

    def test_default_n_results_is_20(self):
        coll = self._make_collection()
        get_similar_dangerous_mails("[0.1, 0.2]", coll)
        self.assertEqual(coll.query.call_args.kwargs["n_results"], 20)

    def test_n_results_kwarg_forwarded(self):
        coll = self._make_collection()
        get_similar_dangerous_mails("[0.1, 0.2]", coll, n_results=5)
        self.assertEqual(coll.query.call_args.kwargs["n_results"], 5)
