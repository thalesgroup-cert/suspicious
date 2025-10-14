"""
This module provides different interfaces allowing the parsing all the configs
from a JSON object.

Mail configuration will be used to both template the email response and send it
using an SMTP client.
"""

import pydantic


class MailConfig(pydantic.BaseModel):
    server: str
    """The SMTP server host."""

    port: int = 25
    """The SMTP server port."""

    username: str = "SUSPICIOUS"
    """The name of the user sending the response email."""

    footer: str = "Limited Distribution"
    """The email footer."""

    group: str = "Your Cybersecurity Team Name"
    """The cybersecurity team name."""

    suspicious_web: str = "https://suspicious.test/submissions/"
    """The URL to the Suspicious web interface."""

    company_name: str = "test.com"
    """The name of the company hosting the Suspicious service."""

    company_url: str = "https://www.test.com/en"
    """The URL to the company's website."""

    socials: dict[str, str] = pydantic.Field(default_factory=dict[str, str])
    """The social URLs to the company's pages. (facebook, twitter, ...)"""

    glossary: str = "https://glossary_to_cyber terms"
    """The URL to the glossary page."""

    inquiry: str = "mailto:inquryemail@yourcompany.com"
    """The company's email address to write to for inquiry request."""

    inquiry_text: str = "inquryemail@yourcompany.com"
    """The label text for the inquiry email address button."""

    security: str = "mailto:yoursecuritymail@yourcompany.com"
    """The company's email address to write to for security concerns."""

    security_msg: str = "yoursecuritymail@yourcompany.com"
    """The label text for the security email address button."""

    logos: dict[str, str] = pydantic.Field(default_factory=dict[str, str])
    """The company and acknowledge-badmail logos. (format: data:image/png;base64)"""
