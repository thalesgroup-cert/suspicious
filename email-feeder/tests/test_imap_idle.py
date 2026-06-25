import logging
import socket
import types

import classes.models.configs.internals.imap as imapcfg
import classes.services.mail_client_service as mail_client_service
import classes.services.mailbox_service as mailbox_service


LOG = logging.getLogger("test-idle")


def _imap_config():
    return imapcfg.IMAPConfig(
        enable=True, host="h", port=143, login="u@x", password="p",
        mailbox_to_monitor="INBOX",
    )


class _FakeSock:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, t):
        self.timeouts.append(t)


class _FakeImap:
    """Minimal raw-imaplib stand-in for the IDLE path."""

    def __init__(self, lines, capabilities=("IDLE",), plus=True):
        self._lines = list(lines)
        self.capabilities = capabilities
        self.sock = _FakeSock()
        self.sent = []
        self._plus = plus
        self._tag = 0

    def _new_tag(self):
        self._tag += 1
        return b"A%03d" % self._tag

    def send(self, data):
        self.sent.append(data)

    def readline(self):
        if not self._lines:
            return b""
        return self._lines.pop(0)


def _client_with(fake):
    client = mail_client_service.MailClient(config=_imap_config(), logger=LOG)
    client._MailClient__imap_client = fake
    return client


def test_has_idle_capability_true():
    client = _client_with(_FakeImap([], capabilities=("IDLE", "UIDPLUS")))
    assert client.has_idle_capability() is True


def test_has_idle_capability_false_when_absent():
    client = _client_with(_FakeImap([], capabilities=("UIDPLUS",)))
    assert client.has_idle_capability() is False


def test_has_idle_capability_false_when_disconnected():
    client = mail_client_service.MailClient(config=_imap_config(), logger=LOG)
    assert client.has_idle_capability() is False


def test_idle_wait_wakes_on_exists():
    fake = _FakeImap([b"+ idling\r\n", b"* 2 EXISTS\r\n"])
    client = _client_with(fake)
    assert client.idle_wait(timeout=5) is True
    # IDLE issued then DONE issued.
    assert any(b"IDLE" in s for s in fake.sent)
    assert any(s == b"DONE\r\n" for s in fake.sent)


def test_idle_wait_false_when_no_continuation():
    fake = _FakeImap([b"A001 BAD no idle\r\n"])
    client = _client_with(fake)
    assert client.idle_wait(timeout=5) is False


def test_idle_wait_false_on_timeout():
    class _TimeoutImap(_FakeImap):
        def readline(self):
            if self.sent and self.sent[-1].endswith(b"IDLE\r\n") and not self._lines:
                # already consumed continuation; simulate blocking timeout
                raise socket.timeout()
            return super().readline()

    fake = _TimeoutImap([b"+ idling\r\n"])
    client = _client_with(fake)
    assert client.idle_wait(timeout=1) is False
    assert any(s == b"DONE\r\n" for s in fake.sent)


def test_idle_wait_false_when_disconnected():
    client = mail_client_service.MailClient(config=_imap_config(), logger=LOG)
    assert client.idle_wait(timeout=1) is False


# --- Mailbox delegation ---

def _mailbox_with_fake_client(fake, select_raises=False):
    import pathlib
    mb = mailbox_service.Mailbox(
        config=_imap_config(), logger=LOG, tmp_path=pathlib.Path("/tmp"),
    )
    client = mb._Mailbox__mail_client
    client._MailClient__imap_client = fake

    if select_raises:
        def _boom(*a, **k):
            raise RuntimeError("select failed")
        client.select = _boom
    else:
        client.select = lambda *a, **k: ("OK", [b""])
    return mb


def test_mailbox_has_idle_capability_delegates():
    mb = _mailbox_with_fake_client(_FakeImap([], capabilities=("IDLE",)))
    assert mb.has_idle_capability() is True


def test_mailbox_idle_wait_selects_then_delegates():
    fake = _FakeImap([b"+ idling\r\n", b"* 1 EXISTS\r\n"])
    mb = _mailbox_with_fake_client(fake)
    assert mb.idle_wait(timeout=5) is True


def test_mailbox_idle_wait_false_when_select_fails():
    fake = _FakeImap([b"+ idling\r\n", b"* 1 EXISTS\r\n"])
    mb = _mailbox_with_fake_client(fake, select_raises=True)
    assert mb.idle_wait(timeout=5) is False


# --- Main-loop wait decision ---

def test_wait_uses_idle_for_single_capable_mailbox():
    import main

    calls = {"idle": 0}
    fake_mb = types.SimpleNamespace(
        has_idle_capability=lambda: True,
        idle_wait=lambda t: calls.__setitem__("idle", calls["idle"] + 1) or True,
    )
    cfg = types.SimpleNamespace(imap_idle=True)
    main._wait_for_next_cycle(cfg, [fake_mb], sleep_interval=0, logger=LOG)
    assert calls["idle"] == 1


def test_wait_sleeps_when_idle_disabled(monkeypatch):
    import main

    slept = {"n": 0}
    monkeypatch.setattr(main.time, "sleep", lambda t: slept.__setitem__("n", slept["n"] + 1))
    fake_mb = types.SimpleNamespace(
        has_idle_capability=lambda: True, idle_wait=lambda t: True,
    )
    cfg = types.SimpleNamespace(imap_idle=False)
    main._wait_for_next_cycle(cfg, [fake_mb], sleep_interval=0, logger=LOG)
    assert slept["n"] == 1


def test_wait_sleeps_with_multiple_mailboxes(monkeypatch):
    import main

    slept = {"n": 0}
    monkeypatch.setattr(main.time, "sleep", lambda t: slept.__setitem__("n", slept["n"] + 1))
    mb = types.SimpleNamespace(has_idle_capability=lambda: True, idle_wait=lambda t: True)
    cfg = types.SimpleNamespace(imap_idle=True)
    main._wait_for_next_cycle(cfg, [mb, mb], sleep_interval=0, logger=LOG)
    assert slept["n"] == 1


def test_wait_sleeps_when_no_idle_capability(monkeypatch):
    import main

    slept = {"n": 0}
    monkeypatch.setattr(main.time, "sleep", lambda t: slept.__setitem__("n", slept["n"] + 1))
    mb = types.SimpleNamespace(has_idle_capability=lambda: False, idle_wait=lambda t: True)
    cfg = types.SimpleNamespace(imap_idle=True)
    main._wait_for_next_cycle(cfg, [mb], sleep_interval=0, logger=LOG)
    assert slept["n"] == 1
