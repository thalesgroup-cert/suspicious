from django.test import SimpleTestCase

from connectors.contrib.ai_narration.select import select_auto_provider, select_provider
from connectors.contrib.ai_narration.providers import anthropic, gemini, ollama, openai, openai_compatible


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

    def test_explicit_narration_provider_wins_over_key_presence(self):
        name, fn = select_provider({
            "narration_provider": "openai_compatible", "openai_api_key": "sk-x",
        })
        self.assertEqual(name, "openai_compatible")
        self.assertIs(fn, openai_compatible.generate)

    def test_explicit_ollama_wins_over_key_presence(self):
        name, _ = select_provider({"narration_provider": "ollama", "openai_api_key": "sk-x"})
        self.assertEqual(name, "ollama")

    def test_unset_or_unknown_narration_provider_falls_back_to_key_presence(self):
        for value in (None, "", "no-such-provider"):
            name, _ = select_provider({"narration_provider": value, "openai_api_key": "sk-x"})
            self.assertEqual(name, "openai")


class SelectAutoProviderTest(SimpleTestCase):
    def test_unset_blank_or_ollama_selects_ollama(self):
        for config in ({}, {"narration_provider": None}, {"narration_provider": ""},
                       {"narration_provider": "  "}, {"narration_provider": "ollama"}):
            name, fn = select_auto_provider(config)
            self.assertEqual(name, "ollama")
            self.assertIs(fn, ollama.generate)

    def test_openai_compatible_selects_openai_compatible(self):
        name, fn = select_auto_provider({"narration_provider": "openai_compatible"})
        self.assertEqual(name, "openai_compatible")
        self.assertIs(fn, openai_compatible.generate)

    def test_vendor_providers_are_not_allowed(self):
        for value in ("openai", "anthropic", "gemini"):
            with self.assertRaises(ValueError):
                select_auto_provider({"narration_provider": value, f"{value}_api_key": "k"})

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            select_auto_provider({"narration_provider": "no-such-provider"})

    def test_api_key_presence_never_changes_the_result(self):
        keys = {"openai_api_key": "sk-x", "anthropic_api_key": "ak-x", "gemini_api_key": "gk-x"}
        name, _ = select_auto_provider(dict(keys))
        self.assertEqual(name, "ollama")
        name, _ = select_auto_provider({**keys, "narration_provider": "openai_compatible"})
        self.assertEqual(name, "openai_compatible")
