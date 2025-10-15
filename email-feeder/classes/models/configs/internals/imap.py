"""
This module provides different interfaces allowing the parsing of IMAP configs
from a JSON object.

The IMAP configuration will be used to receive and store emails from a user for
the analysis processs.
"""

import pydantic


class IMAPConfig(pydantic.BaseModel):
    enable: bool
    """Whether this current config is useable."""

    host: str
    """The IMAP host server."""

    port: int
    """The IMAP port the server is listening on."""

    login: str
    """The login of the user on the IMAP server. (format: user@example.com)"""

    password: str
    """The password of the user on the IMAP server."""

    mailbox_to_monitor: str
    """The default mailbox to watch on the IMAP server. (INBOX)"""

    certfile: str | None = pydantic.Field(default=None)
    """The certfile to use during SSL handshake with the IMAP server. (file path)"""

    keyfile: str | None = pydantic.Field(default=None)
    """The keyfile to use during SSL handshake with the IMAP server. (file path)"""

    rootcafile: str | None = pydantic.Field(default=None)
    """The root CA file to use during SSL handshake with the IMAP server. (file path)"""
