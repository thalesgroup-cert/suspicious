"""Submission size/count caps — bound memory/disk against hostile mail."""


class CapsExceeded(Exception):
    """Raised when a submission exceeds the configured caps."""


def check_caps(attachments, wrapper_bytes: int, caps) -> None:
    if len(attachments) > caps.max_attachments:
        raise CapsExceeded(
            f"{len(attachments)} attachments > max {caps.max_attachments}")
    total = wrapper_bytes
    for att in attachments:
        size = len(att.content or b"")
        if size > caps.max_attachment_bytes:
            raise CapsExceeded(
                f"attachment {size} bytes > max {caps.max_attachment_bytes}")
        total += size
    if total > caps.max_total_bytes:
        raise CapsExceeded(f"total {total} bytes > max {caps.max_total_bytes}")
