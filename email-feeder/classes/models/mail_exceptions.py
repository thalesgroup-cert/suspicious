class MailboxConnectionError(Exception):
    """Custom exception for issues related to connecting to the mailbox."""

    pass


class MailboxOperationError(Exception):
    """Custom exception for errors during IMAP operations after connection."""

    pass
