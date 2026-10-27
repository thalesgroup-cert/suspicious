import logging
import unittest
from unittest.mock import MagicMock

import classes.models.mail_exceptions
from classes.services.mailbox_service import Mailbox


class FetchKeepsUnseenTest(unittest.TestCase):
    def test_inbox_fetch_does_not_set_seen(self):
        service = Mailbox.__new__(Mailbox)
        client = MagicMock()
        client.fetch.side_effect = classes.models.mail_exceptions.MailboxOperationError("stop here")
        service._Mailbox__mail_client = client
        service._Mailbox__logger = logging.getLogger("test")

        service.process_inbox_email(b"1", "ref")

        # A plain RFC822 fetch sets \Seen, so a failed upload would lose the mail.
        self.assertEqual(client.fetch.call_args.kwargs["message_parts"], "(BODY.PEEK[])")
