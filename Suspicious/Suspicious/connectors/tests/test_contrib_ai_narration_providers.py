from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.ai_narration.providers import anthropic, gemini, ollama, openai


class OllamaProviderTest(SimpleTestCase):
    @mock.patch("connectors.contrib.ai_narration.providers.ollama.requests.post")
    def test_generate_posts_expected_shape_and_parses_response(self, mock_post):
        mock_post.return_value = mock.Mock(
            json=lambda: {"response": "hello from ollama"},
        )
        mock_post.return_value.raise_for_status = lambda: None
        text = ollama.generate("a prompt", {"ollama_url": "http://x:11434", "ollama_model": "qwen2.5:7b-instruct"})
        self.assertEqual(text, "hello from ollama")
        url, kwargs = mock_post.call_args
        self.assertEqual(url[0], "http://x:11434/api/generate")
        self.assertEqual(kwargs["json"]["model"], "qwen2.5:7b-instruct")
        self.assertEqual(kwargs["json"]["prompt"], "a prompt")

    @mock.patch("connectors.contrib.ai_narration.providers.ollama.requests.post")
    def test_generate_uses_defaults_when_config_empty(self, mock_post):
        mock_post.return_value = mock.Mock(json=lambda: {"response": "x"})
        mock_post.return_value.raise_for_status = lambda: None
        ollama.generate("p", {})
        url, kwargs = mock_post.call_args
        self.assertEqual(url[0], "http://localhost:11434/api/generate")
        self.assertEqual(kwargs["json"]["model"], "qwen2.5:7b-instruct")


class OpenAIProviderTest(SimpleTestCase):
    @mock.patch("connectors.contrib.ai_narration.providers.openai.requests.post")
    def test_generate_posts_expected_shape_and_parses_response(self, mock_post):
        mock_post.return_value = mock.Mock(
            json=lambda: {"choices": [{"message": {"content": "hello from openai"}}]},
        )
        mock_post.return_value.raise_for_status = lambda: None
        text = openai.generate("a prompt", {"openai_api_key": "sk-test", "openai_model": "gpt-4o-mini"})
        self.assertEqual(text, "hello from openai")
        url, kwargs = mock_post.call_args
        self.assertEqual(url[0], "https://api.openai.com/v1/chat/completions")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sk-test")
        self.assertEqual(kwargs["json"]["messages"][0]["content"], "a prompt")


class AnthropicProviderTest(SimpleTestCase):
    @mock.patch("connectors.contrib.ai_narration.providers.anthropic.requests.post")
    def test_generate_posts_expected_shape_and_parses_response(self, mock_post):
        mock_post.return_value = mock.Mock(
            json=lambda: {"content": [{"text": "hello from anthropic"}]},
        )
        mock_post.return_value.raise_for_status = lambda: None
        text = anthropic.generate("a prompt", {"anthropic_api_key": "ak-test"})
        self.assertEqual(text, "hello from anthropic")
        url, kwargs = mock_post.call_args
        self.assertEqual(url[0], "https://api.anthropic.com/v1/messages")
        self.assertEqual(kwargs["headers"]["x-api-key"], "ak-test")
        self.assertEqual(kwargs["json"]["messages"][0]["content"], "a prompt")


class GeminiProviderTest(SimpleTestCase):
    @mock.patch("connectors.contrib.ai_narration.providers.gemini.requests.post")
    def test_generate_posts_expected_shape_and_parses_response(self, mock_post):
        mock_post.return_value = mock.Mock(
            json=lambda: {"candidates": [{"content": {"parts": [{"text": "hello from gemini"}]}}]},
        )
        mock_post.return_value.raise_for_status = lambda: None
        text = gemini.generate("a prompt", {"gemini_api_key": "gk-test", "gemini_model": "gemini-2.5-flash"})
        self.assertEqual(text, "hello from gemini")
        url, kwargs = mock_post.call_args
        self.assertIn("gemini-2.5-flash", url[0])
        self.assertEqual(kwargs["headers"]["x-goog-api-key"], "gk-test")
        self.assertEqual(kwargs["json"]["contents"][0]["parts"][0]["text"], "a prompt")
