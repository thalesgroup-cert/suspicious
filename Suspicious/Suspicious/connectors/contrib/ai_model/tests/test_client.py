from unittest import mock

import requests
from django.test import SimpleTestCase

from connectors.contrib.ai_model.client import AiInferenceClient
from connectors.providers import ProviderUnavailable

URL = "http://ai_inference:8090"


def reply(status, body=None, text=""):
    response = mock.Mock(status_code=status, text=text or str(body))
    if body is None:
        response.json.side_effect = ValueError("not json")
    else:
        response.json.return_value = body
    return response


def client_with(**methods):
    client = AiInferenceClient(URL + "/", "s3cret", 7)
    client.session = mock.Mock(**methods)
    return client


class ClassifyTest(SimpleTestCase):
    def test_posts_the_body_with_the_token_and_returns_the_json(self):
        client = client_with(post=mock.Mock(return_value=reply(200, {"results": {}})))
        self.assertEqual(client.classify("hello"), {"results": {}})
        client.session.post.assert_called_once_with(
            f"{URL}/v2/models/ai_mail/classify",
            json={"mail_body": "hello", "versions": ["active"]},
            headers={"Authorization": "Bearer s3cret"}, timeout=7,
        )

    def test_connection_errors_and_timeouts_are_retryable(self):
        for error in (requests.ConnectionError("down"), requests.Timeout("slow")):
            with self.subTest(error=type(error).__name__):
                client = client_with(post=mock.Mock(side_effect=error))
                with self.assertRaises(ProviderUnavailable) as caught:
                    client.classify("x")
                self.assertTrue(caught.exception.retryable)

    def test_5xx_is_retryable(self):
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                client = client_with(post=mock.Mock(return_value=reply(status, {"detail": "boom"})))
                with self.assertRaises(ProviderUnavailable) as caught:
                    client.classify("x")
                self.assertTrue(caught.exception.retryable)
                self.assertIn(str(status), str(caught.exception))

    def test_a_503_that_only_an_operator_can_fix_is_not_retryable(self):
        details = (
            "Required models unavailable for variant 'personal': safe_model (looked in /m)",
            "Vectorizer unavailable: boom",
            "token not configured",
        )
        for detail in details:
            with self.subTest(detail=detail):
                client = client_with(post=mock.Mock(return_value=reply(503, {"detail": detail})))
                with self.assertRaises(ProviderUnavailable) as caught:
                    client.classify("x")
                self.assertFalse(caught.exception.retryable)
                self.assertIn(detail[:20], str(caught.exception))

    def test_any_other_503_stays_retryable(self):
        details = (
            "busy",
            # The server restarting: the vectorizer is loading and the next try may find it ready.
            "Vectorizer unavailable: still loading, try again shortly",
        )
        for detail in details:
            with self.subTest(detail=detail):
                client = client_with(post=mock.Mock(return_value=reply(503, {"detail": detail})))
                with self.assertRaises(ProviderUnavailable) as caught:
                    client.classify("x")
                self.assertTrue(caught.exception.retryable)

    def test_a_refused_setup_fails_at_once_without_retry_and_without_the_token(self):
        for status in (401, 403, 404, 407, 408, 429):
            with self.subTest(status=status):
                client = client_with(post=mock.Mock(return_value=reply(status, {"detail": "nope"})))
                with self.assertRaises(ProviderUnavailable) as caught:
                    client.classify("x")
                self.assertFalse(caught.exception.retryable)
                self.assertIn(f"HTTP {status}", str(caught.exception))
                self.assertNotIn("s3cret", str(caught.exception))
        client = client_with(post=mock.Mock(return_value=reply(401, {"detail": "x"})))
        with self.assertRaises(ProviderUnavailable) as caught:
            client.classify("x")
        self.assertEqual(str(caught.exception), "inference server rejected the token (HTTP 401)")

    def test_a_refusal_of_this_request_is_a_value_error_and_never_echoes_the_token(self):
        for status in (400, 409, 413, 422):  # 409: an unlisted 4xx counts as request-specific
            with self.subTest(status=status):
                client = client_with(post=mock.Mock(return_value=reply(status, {"detail": "nope"})))
                with self.assertRaises(ValueError) as caught:
                    client.classify("x")
                self.assertNotIsInstance(caught.exception, ProviderUnavailable)
                self.assertEqual(str(caught.exception), f"inference server refused the request (HTTP {status})")

    def test_a_non_json_200_is_a_permanent_unavailable(self):
        client = client_with(post=mock.Mock(return_value=reply(200, None, text="<html>")))
        with self.assertRaises(ProviderUnavailable) as caught:
            client.classify("x")
        self.assertFalse(caught.exception.retryable)


class ReadyTest(SimpleTestCase):
    def test_ready_and_token_accepted(self):
        client = client_with(get=mock.Mock(side_effect=[reply(200, {"ready": True}), reply(200, {})]))
        self.assertEqual(client.ready()[0], True)
        urls = [call.args[0] for call in client.session.get.call_args_list]
        self.assertEqual(urls, [f"{URL}/v2/health/ready", f"{URL}/v2/models/ai_mail"])
        self.assertEqual(client.session.get.call_args_list[1].kwargs["headers"],
                         {"Authorization": "Bearer s3cret"})

    def test_not_ready_stops_before_the_token_check(self):
        client = client_with(get=mock.Mock(return_value=reply(503, {"ready": False})))
        ok, detail = client.ready()
        self.assertFalse(ok)
        self.assertIn("503", detail)
        self.assertEqual(client.session.get.call_count, 1)

    def test_a_rejected_token_is_not_ok(self):
        client = client_with(get=mock.Mock(side_effect=[reply(200, {}), reply(401, {"detail": "x"})]))
        ok, detail = client.ready()
        self.assertFalse(ok)
        self.assertIn("token", detail)

    def test_unreachable_is_not_ok_and_never_raises(self):
        client = client_with(get=mock.Mock(side_effect=requests.ConnectionError("down")))
        ok, detail = client.ready()
        self.assertFalse(ok)
        self.assertIn("ConnectionError", detail)
