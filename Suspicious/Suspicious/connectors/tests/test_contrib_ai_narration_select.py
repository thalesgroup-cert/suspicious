from django.test import SimpleTestCase

from connectors.contrib.ai_narration.select import select_provider
from connectors.contrib.ai_narration.providers import anthropic, gemini, ollama, openai


class SelectProviderTest(SimpleTestCase):
    def test_no_keys_configured_falls_back_to_ollama(self):
        name, fn = select_provider({})
        self.assertEqual(name, "ollama")
        self.assertIs(fn, ollama.generate)

    def test_openai_key_selects_openai(self):
        name, fn = select_provider({"openai_api_key": "sk-x"})
        self.assertEqual(name, "openai")
        self.assertIs(fn, openai.generate)

    def test_anthropic_key_selects_anthropic(self):
        name, fn = select_provider({"anthropic_api_key": "ak-x"})
        self.assertEqual(name, "anthropic")
        self.assertIs(fn, anthropic.generate)

    def test_gemini_key_selects_gemini(self):
        name, fn = select_provider({"gemini_api_key": "gk-x"})
        self.assertEqual(name, "gemini")
        self.assertIs(fn, gemini.generate)

    def test_priority_order_openai_before_anthropic_before_gemini(self):
        name, _ = select_provider({
            "openai_api_key": "sk-x", "anthropic_api_key": "ak-x", "gemini_api_key": "gk-x",
        })
        self.assertEqual(name, "openai")
        name, _ = select_provider({"anthropic_api_key": "ak-x", "gemini_api_key": "gk-x"})
        self.assertEqual(name, "anthropic")

    def test_empty_string_key_does_not_count_as_configured(self):
        name, _ = select_provider({"openai_api_key": ""})
        self.assertEqual(name, "ollama")
