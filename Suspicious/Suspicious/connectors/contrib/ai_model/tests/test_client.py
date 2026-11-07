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

    def test_sends_the_case_to_leave_out_of_the_neighbour_vote(self):
        client = client_with(post=mock.Mock(return_value=reply(200, {"results": {}})))
        client.classify("hello", exclude_case_ids=[42])
        self.assertEqual(client.session.post.call_args.kwargs["json"],
                         {"mail_body": "hello", "versions": ["active"], "exclude_case_ids": [42]})

    def test_sends_the_requested_versions(self):
        client = client_with(post=mock.Mock(return_value=reply(200, {"results": {}})))
        client.classify("hello", versions=("active", "shadow"))
        self.assertEqual(client.session.post.call_args.kwargs["json"]["versions"], ["active", "shadow"])

    def test_metadata_gets_the_model_path(self):
        client = client_with(get=mock.Mock(return_value=reply(200, {"versions": {}})))
        self.assertEqual(client.metadata(), {"versions": {}})
        self.assertEqual(client.session.get.call_args.args[0], f"{URL}/v2/models/ai_mail")

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
                self.assertEqual(str(caught.exception), f"inference server HTTP {status}")

    def test_a_503_that_only_an_operator_can_fix_is_not_retryable(self):
        # The message names the matched fixed phrase only, never the rest of the server's detail.
        details = (
            ("Required models unavailable for variant 'personal': safe_model (looked in /m)",
             "models unavailable"),
            ("Vectorizer unavailable: boom", "vectorizer unavailable"),
            ("token not configured", "token not configured"),
        )
        for detail, phrase in details:
            with self.subTest(detail=detail):
                client = client_with(post=mock.Mock(return_value=reply(503, {"detail": detail})))
                with self.assertRaises(ProviderUnavailable) as caught:
                    client.classify("x")
                self.assertFalse(caught.exception.retryable)
                self.assertEqual(str(caught.exception), f"inference server HTTP 503: {phrase}")

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
                self.assertEqual(str(caught.exception), "inference server HTTP 503")

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

    def test_a_404_names_the_real_path(self):
        client = client_with(post=mock.Mock(return_value=reply(404, {"detail": "Not Found"})))
        with self.assertRaises(ProviderUnavailable) as caught:
            client.embed(["x"], "classifier")
        self.assertEqual(
            str(caught.exception),
            "inference server has no /v2/embed endpoint, check the url and the image version (HTTP 404)",
        )
        with self.assertRaises(ProviderUnavailable) as caught:
            client.classify("x")
        self.assertIn("no /v2/models/ai_mail/classify endpoint", str(caught.exception))

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


class EmbedTest(SimpleTestCase):
    def test_posts_texts_and_profile_with_the_token_and_returns_the_json(self):
        answer = {"vectors": [[0.1]], "preprocessing_version": "legacy-first128", "embedding_version": "cmp-e1"}
        client = client_with(post=mock.Mock(return_value=reply(200, answer)))
        self.assertEqual(client.embed(["hi"], "campaign"), answer)
        client.session.post.assert_called_once_with(
            f"{URL}/v2/embed", json={"texts": ["hi"], "profile": "campaign"},
            headers={"Authorization": "Bearer s3cret"}, timeout=7,
        )

    def test_sends_the_preprocessing_when_given(self):
        client = client_with(post=mock.Mock(return_value=reply(200, {"vectors": []})))
        client.embed(["hi"], "classifier", preprocessing="chunkmean-tokens-v1")
        self.assertEqual(client.session.post.call_args.kwargs["json"],
                         {"texts": ["hi"], "profile": "classifier", "preprocessing": "chunkmean-tokens-v1"})

    def test_503_is_provider_unavailable(self):
        client = client_with(post=mock.Mock(return_value=reply(503, {"detail": "Vectorizer unavailable: still loading"})))
        with self.assertRaises(ProviderUnavailable) as caught:
            client.embed(["hi"], "classifier")
        self.assertTrue(caught.exception.retryable)

    def test_error_text_carries_the_status_never_the_body(self):
        client = client_with(post=mock.Mock(return_value=reply(422, {"detail": "SECRET MAIL TEXT"}, text="SECRET MAIL TEXT")))
        with self.assertRaises(ValueError) as caught:
            client.embed(["SECRET MAIL TEXT"], "classifier")
        self.assertIn("422", str(caught.exception))
        self.assertNotIn("SECRET", str(caught.exception))


class TrainTest(SimpleTestCase):
    H = {"Authorization": "Bearer s3cret"}

    def test_train_posts_the_body_and_accepts_202_and_200(self):
        for status in (202, 200):
            with self.subTest(status=status):
                client = client_with(post=mock.Mock(return_value=reply(status, {"state": "queued"})))
                self.assertEqual(client.train({"job_id": "j"}), {"state": "queued"})
                client.session.post.assert_called_once_with(
                    f"{URL}/v2/train", json={"job_id": "j"}, headers=self.H, timeout=7)

    def test_train_409_is_server_busy(self):
        from connectors.contrib.ai_model.client import ServerBusy
        client = client_with(post=mock.Mock(return_value=reply(409, {"detail": "x"})))
        with self.assertRaises(ServerBusy):
            client.train({})

    def test_train_status_gets_the_job_and_404_is_a_distinct_error(self):
        from connectors.contrib.ai_model.client import TrainJobGone
        client = client_with(get=mock.Mock(return_value=reply(200, {"state": "running"})))
        self.assertEqual(client.train_status("j-1"), {"state": "running"})
        client.session.get.assert_called_once_with(f"{URL}/v2/train/j-1", headers=self.H, timeout=7)
        client = client_with(get=mock.Mock(return_value=reply(404, {"detail": "unknown"})))
        with self.assertRaises(TrainJobGone):
            client.train_status("j-1")

    def test_train_status_408_and_429_mean_try_later(self):
        from connectors.contrib.ai_model.client import TryLater
        for status in (408, 429):
            client = client_with(get=mock.Mock(return_value=reply(status, {"detail": "slow"})))
            with self.subTest(status=status), self.assertRaises(TryLater):
                client.train_status("j-1")

    def test_train_status_errors_are_status_only(self):
        client = client_with(get=mock.Mock(return_value=reply(500, text="X-Amz-Signature=abc")))
        with self.assertRaises(ProviderUnavailable) as caught:
            client.train_status("j-1")
        self.assertNotIn("Amz", str(caught.exception))
        client = client_with(get=mock.Mock(side_effect=requests.ConnectionError("http://rustfs?sig")))
        with self.assertRaises(ProviderUnavailable) as caught:
            client.train_status("j-1")
        self.assertNotIn("rustfs", str(caught.exception))

    def test_cancel_and_reload(self):
        from connectors.contrib.ai_model.client import ServerBusy
        client = client_with(post=mock.Mock(return_value=reply(202, {"state": "cancelled"})))
        self.assertEqual(client.train_cancel("j-1"), {"state": "cancelled"})
        client.session.post.assert_called_once_with(
            f"{URL}/v2/train/j-1/cancel", json={}, headers=self.H, timeout=7)
        client = client_with(post=mock.Mock(return_value=reply(200, {"active": {}})))
        self.assertEqual(client.reload({"active": None, "shadow": None}), {"active": {}})
        self.assertEqual(client.session.post.call_args.args[0], f"{URL}/v2/reload")
        client = client_with(post=mock.Mock(return_value=reply(409, {})))
        with self.assertRaises(ServerBusy):
            client.reload({"active": None, "shadow": None})
        client = client_with(post=mock.Mock(return_value=reply(422, text="https://rustfs/x?X-Amz-Signature=s")))
        with self.assertRaises(ValueError) as caught:
            client.reload({"active": None, "shadow": None})
        self.assertNotIn("rustfs", str(caught.exception))
