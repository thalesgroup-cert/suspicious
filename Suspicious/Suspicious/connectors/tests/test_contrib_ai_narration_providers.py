from unittest import mock

from django.test import SimpleTestCase

from connectors.contrib.ai_narration.providers import anthropic, gemini, ollama, openai, openai_compatible


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
        self.assertEqual(kwargs["json"]["options"]["num_ctx"], 8192)

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


def _ok_response(content="hello from compat"):
    response = mock.Mock(json=lambda: {"choices": [{"message": {"content": content}}]})
    response.raise_for_status = lambda: None
    return response


class OpenAICompatibleProviderTest(SimpleTestCase):
    _CONFIG = {
        "openai_compatible_base_url": "https://gw.internal/v1",
        "openai_compatible_model": "my-model",
    }

    @mock.patch("connectors.contrib.ai_narration.providers.openai_compatible.requests.post")
    def test_generate_posts_expected_shape_and_parses_response(self, mock_post):
        mock_post.return_value = _ok_response()
        text = openai_compatible.generate("a prompt", self._CONFIG)
        self.assertEqual(text, "hello from compat")
        url, kwargs = mock_post.call_args
        self.assertEqual(url[0], "https://gw.internal/v1/chat/completions")
        self.assertEqual(kwargs["json"]["model"], "my-model")
        self.assertEqual(kwargs["json"]["messages"][0]["content"], "a prompt")

    @mock.patch("connectors.contrib.ai_narration.providers.openai_compatible.requests.post")
    def test_trailing_slash_on_base_url_does_not_double_up(self, mock_post):
        mock_post.return_value = _ok_response()
        openai_compatible.generate(
            "p", {**self._CONFIG, "openai_compatible_base_url": "https://gw.internal/v1/"},
        )
        self.assertEqual(mock_post.call_args[0][0], "https://gw.internal/v1/chat/completions")

    @mock.patch("connectors.contrib.ai_narration.providers.openai_compatible.requests.post")
    def test_non_v1_version_prefix_is_preserved(self, mock_post):
        mock_post.return_value = _ok_response()
        openai_compatible.generate(
            "p", {**self._CONFIG, "openai_compatible_base_url": "https://open.bigmodel.cn/api/paas/v4"},
        )
        self.assertEqual(
            mock_post.call_args[0][0], "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        )

    @mock.patch("connectors.contrib.ai_narration.providers.openai_compatible.requests.post")
    def test_authorization_header_present_with_key(self, mock_post):
        mock_post.return_value = _ok_response()
        openai_compatible.generate("p", {**self._CONFIG, "openai_compatible_api_key": "k-test"})
        self.assertEqual(mock_post.call_args[1]["headers"]["Authorization"], "Bearer k-test")

    @mock.patch("connectors.contrib.ai_narration.providers.openai_compatible.requests.post")
    def test_authorization_header_absent_without_key(self, mock_post):
        mock_post.return_value = _ok_response()
        openai_compatible.generate("p", self._CONFIG)
        self.assertNotIn("Authorization", mock_post.call_args[1]["headers"])
        openai_compatible.generate("p", {**self._CONFIG, "openai_compatible_api_key": ""})
        self.assertNotIn("Authorization", mock_post.call_args[1]["headers"])

    @mock.patch("connectors.contrib.ai_narration.providers.openai_compatible.requests.post")
    def test_missing_base_url_raises_without_calling_endpoint(self, mock_post):
        for config in ({"openai_compatible_model": "m"}, {**self._CONFIG, "openai_compatible_base_url": "  "}):
            with self.assertRaises(ValueError):
                openai_compatible.generate("p", config)
        mock_post.assert_not_called()

    @mock.patch("connectors.contrib.ai_narration.providers.openai_compatible.requests.post")
    def test_non_http_base_url_raises(self, mock_post):
        with self.assertRaises(ValueError):
            openai_compatible.generate(
                "p", {**self._CONFIG, "openai_compatible_base_url": "ftp://gw.internal/v1"},
            )
        mock_post.assert_not_called()

    @mock.patch("connectors.contrib.ai_narration.providers.openai_compatible.requests.post")
    def test_missing_model_raises(self, mock_post):
        with self.assertRaises(ValueError):
            openai_compatible.generate(
                "p", {"openai_compatible_base_url": "https://gw.internal/v1"},
            )
        mock_post.assert_not_called()

    @mock.patch("connectors.contrib.ai_narration.providers.openai_compatible.requests.post")
    def test_empty_content_raises(self, mock_post):
        for content in ("", None):
            mock_post.return_value = _ok_response(content)
            with self.assertRaises(ValueError):
                openai_compatible.generate("p", self._CONFIG)
