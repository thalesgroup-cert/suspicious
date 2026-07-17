import pytest
from classes.services.caps import check_caps, CapsExceeded


class _Caps:
    def __init__(self, n, per, total):
        self.max_attachments = n
        self.max_attachment_bytes = per
        self.max_total_bytes = total


class _Att:
    def __init__(self, content):
        self.content = content


def test_within_caps_ok():
    check_caps([_Att(b"ab"), _Att(b"cd")], 10, _Caps(50, 100, 100))


def test_too_many_attachments():
    with pytest.raises(CapsExceeded):
        check_caps([_Att(b"a")] * 3, 0, _Caps(2, 100, 100))


def test_attachment_too_big():
    with pytest.raises(CapsExceeded):
        check_caps([_Att(b"x" * 20)], 0, _Caps(50, 10, 1000))


def test_total_too_big():
    with pytest.raises(CapsExceeded):
        check_caps([_Att(b"x" * 30)], 30, _Caps(50, 100, 50))
