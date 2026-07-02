from unittest import mock

from django.test import SimpleTestCase

from score_process.score_utils.send_mail.send_email_service import SendMailService


class SendHtmlTest(SimpleTestCase):
    def _run(self, smtp):
        """Run send_html with all network methods mocked; return (call order,
        publish kwargs, constructor kwargs)."""
        order = []
        published = {}
        with mock.patch.object(SendMailService, "__init__", return_value=None) as init, \
             mock.patch.object(SendMailService, "connect", lambda self: order.append("connect")), \
             mock.patch.object(SendMailService, "start_tls", lambda self: order.append("tls")), \
             mock.patch.object(SendMailService, "login", lambda self: order.append("login")), \
             mock.patch.object(SendMailService, "close", lambda self: order.append("close")), \
             mock.patch.object(
                 SendMailService, "publish_email",
                 lambda self, **kw: (order.append("publish"), published.update(kw)),
             ):
            SendMailService.send_html(
                smtp, sender="cert@x", recipient="user@x",
                subject="Hi", html="<b>hi</b>",
            )
        return order, published, init.call_args.kwargs

    def test_full_sequence_with_tls(self):
        order, published, _ = self._run({"tls": True})
        self.assertEqual(order, ["connect", "tls", "login", "publish", "close"])
        self.assertEqual(published["sender"], "cert@x")
        self.assertEqual(published["recipient"], "user@x")
        self.assertEqual(published["subject"], "Hi")
        self.assertEqual(published["html"], "<b>hi</b>")

    def test_no_tls_skips_starttls(self):
        order, _, _ = self._run({"tls": False})
        self.assertEqual(order, ["connect", "login", "publish", "close"])

    def test_missing_config_uses_sane_defaults(self):
        # Regression: the old acknowledge copy defaulted port/host to {}.
        _, _, ctor = self._run({})
        self.assertEqual(ctor, {"host": "", "port": 587, "login": "", "password": ""})

    def test_populated_config_passes_through(self):
        _, _, ctor = self._run({
            "server": "smtp.x", "port": 25, "username": "u", "password": "p",
        })
        self.assertEqual(ctor, {"host": "smtp.x", "port": 25, "login": "u", "password": "p"})

    def test_crlf_in_recipient_is_rejected_before_send(self):
        svc = SendMailService(host="h", port=25, login="l", password="p")
        svc._SendMailService__server = mock.Mock()
        with self.assertRaises(ValueError):
            svc.publish_email(
                subject="Hi", sender="cert@x",
                recipient="user@x\r\nBcc: attacker@evil.test",
                html="<b>hi</b>",
            )
        svc._SendMailService__server.sendmail.assert_not_called()
