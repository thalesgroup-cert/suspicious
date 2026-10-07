"""Parser purity and one-document-per-case in ChromaDB."""
import json
from unittest.mock import patch

from django.test import SimpleTestCase

from score_process.score_utils.chromadb_utils import add_to_suspicious_collection
from score_process.scoring.cortex_analyzers.contrib.ai_mail import AiMailParser

FULL = {
    "classification": "DANGEROUS", "sub_classification": "Phishing", "malscore": 9.0, "confidence": 0.9,
    "report": {"analyzed_mail_content": "pay now", "email_embedding": json.dumps([[0.1, 0.2]]),
               "analyzed_mail_headers": {"Subject": ["Pay"]}},
}

class ChromaIdempotenceTest(SimpleTestCase):
    def test_same_case_is_stored_once(self):
        store = {}

        class Coll:
            def get(self, ids):
                return {"ids": [i for i in ids if i in store]}

            def add(self, ids, **kw):
                assert ids not in store, "duplicate id"
                store[ids] = kw

        coll = Coll()
        add_to_suspicious_collection(FULL, "", "", 7, coll)
        add_to_suspicious_collection(FULL, "", "", 7, coll)  # reconcile re-parses the report
        self.assertEqual(len(store), 1)


class ParserIsPureTest(SimpleTestCase):
    def test_parsing_touches_neither_chroma_nor_thehive(self):
        p = AiMailParser(analyzer_name="AI_Mail_Analyzer_1_4", data="d", data_type="file", case_id=7)
        with patch("common.clients.get_chroma_client") as chroma, patch("requests.sessions.Session.request") as http:
            result = p.parse({"malscore": 9.0, "confidence": 0.9, "classification": "DANGEROUS"}, FULL)
        self.assertEqual(result.score, 9)
        chroma.assert_not_called()
        http.assert_not_called()
