from unittest import mock

import pytest

from classes.services.send_mail_service import SendMailService


def test_crlf_in_recipient_is_rejected_before_send():
    svc = SendMailService(host="h", port=25, login="l", password="p")
    svc._SendMailService__server = mock.Mock()
    with pytest.raises(ValueError):
        svc.publish_email(
            subject="Hi",
            sender="feeder@x",
            recipient="user@x\r\nBcc: attacker@evil.test",
            html="<b>hi</b>",
        )
    svc._SendMailService__server.sendmail.assert_not_called()
