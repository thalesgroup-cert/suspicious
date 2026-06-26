"""A forwarded email attached as message/rfc822 must be recovered regardless of
its Content-Transfer-Encoding. Some clients (and Python's own add_attachment for
a message payload given as bytes) emit base64-encoded message/rfc822 parts;
the feeder previously only handled the 7bit/8bit nested-EmailMessage case and
saved mis-decoded data, producing a garbage email.json (null From, base64 body).
"""
import email
import email.message
import email.policy

import classes.services.mailbox_service as ms


def _rfc822_part(cte: str):
    inner = email.message.EmailMessage()
    inner["From"] = "attacker@evil.test"
    inner["To"] = "victim@corp.test"
    inner["Subject"] = "Phish"
    inner.set_content("click http://evil.test")

    wrap = email.message.EmailMessage()
    wrap["From"] = "reporter@corp.test"
    wrap["Subject"] = "fwd"
    wrap.set_content("note")
    if cte == "base64":
        # bytes payload -> Python encodes the message/rfc822 part as base64
        wrap.add_attachment(inner.as_bytes(), maintype="message",
                            subtype="rfc822", filename="p.eml")
    else:
        wrap.add_attachment(inner, filename="p.eml")  # 7bit/8bit nested message

    parsed = email.message_from_bytes(wrap.as_bytes(), policy=email.policy.default)
    for p in parsed.walk():
        if p.get_content_type() == "message/rfc822":
            return p
    raise AssertionError("no rfc822 part built")


def test_base64_rfc822_inner_recovered():
    part = _rfc822_part("base64")
    raw = ms.Mailbox._rfc822_inner_bytes(part)
    m = email.message_from_bytes(raw, policy=email.policy.default)
    assert m["From"] == "attacker@evil.test"
    assert m["Subject"] == "Phish"


def test_nested_rfc822_inner_recovered():
    part = _rfc822_part("8bit")
    raw = ms.Mailbox._rfc822_inner_bytes(part)
    m = email.message_from_bytes(raw, policy=email.policy.default)
    assert m["From"] == "attacker@evil.test"
    assert m["Subject"] == "Phish"
