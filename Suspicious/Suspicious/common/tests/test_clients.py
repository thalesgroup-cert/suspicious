import os
from unittest import mock

from django.test import SimpleTestCase


class GetChromaClientTest(SimpleTestCase):
    def test_builds_http_client_from_section(self):
        section = {"host": "chromadb", "port": 8000}
        with mock.patch.dict(os.environ, {"CHROMA_TOKEN": "tok"}), \
             mock.patch("common.clients.get_section", return_value=section), \
             mock.patch("common.clients.chromadb") as chroma_mod:
            from common.clients import get_chroma_client
            get_chroma_client()
        chroma_mod.HttpClient.assert_called_once()
        kwargs = chroma_mod.HttpClient.call_args.kwargs
        self.assertEqual((kwargs["host"], kwargs["port"]), ("chromadb", 8000))

    def test_uses_defaults_when_keys_absent(self):
        section = {}
        with mock.patch.dict(os.environ, {"CHROMA_TOKEN": "tok"}), \
             mock.patch("common.clients.get_section", return_value=section), \
             mock.patch("common.clients.chromadb") as chroma_mod:
            from common.clients import get_chroma_client
            get_chroma_client()
        kwargs = chroma_mod.HttpClient.call_args.kwargs
        self.assertEqual(kwargs["host"], "chromadb")
        self.assertEqual(kwargs["port"], 8000)

    def test_sends_token_header(self):
        with mock.patch.dict(os.environ, {"CHROMA_TOKEN": "tok"}, clear=False), \
             mock.patch("common.clients.get_section", return_value={"host": "chromadb", "port": 8000}), \
             mock.patch("common.clients.chromadb") as chroma_mod:
            from common.clients import get_chroma_client
            get_chroma_client()
        self.assertEqual(chroma_mod.HttpClient.call_args.kwargs["headers"], {"X-Chroma-Token": "tok"})

    def test_section_token_wins_over_env(self):
        with mock.patch.dict(os.environ, {"CHROMA_TOKEN": "env"}), \
             mock.patch("common.clients.get_section", return_value={"token": "cfg"}), \
             mock.patch("common.clients.chromadb") as chroma_mod:
            from common.clients import get_chroma_client
            get_chroma_client()
        self.assertEqual(chroma_mod.HttpClient.call_args.kwargs["headers"]["X-Chroma-Token"], "cfg")

    def test_missing_token_is_an_error_not_an_anonymous_client(self):
        env = {k: v for k, v in os.environ.items() if k != "CHROMA_TOKEN"}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch("common.clients.get_section", return_value={}), \
             mock.patch("common.clients.chromadb") as chroma_mod:
            from common.clients import get_chroma_client
            with self.assertRaises(RuntimeError):
                get_chroma_client()
        chroma_mod.HttpClient.assert_not_called()
