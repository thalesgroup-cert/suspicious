import logging
import pathlib
import types

import classes.models.configs.internals.imap as imapcfg
from classes.services.mailbox_setup_service import diff_mailbox_configs, apply_mailbox_diff


def _imap(enable=True, host="h", port=143, login="u@x", **kw):
    return imapcfg.IMAPConfig(
        enable=enable, host=host, port=port, login=login, password="p",
        mailbox_to_monitor="INBOX", **kw,
    )


def _config(imap=None, imaps=None):
    conns = types.SimpleNamespace(imap=imap or {}, imaps=imaps or {})
    return types.SimpleNamespace(mail_connectors=conns)


def test_new_enabled_connector_starts():
    old = _config(imap={"a": _imap()})
    new = _config(imap={"a": _imap(), "b": _imap()})
    start, stop = diff_mailbox_configs(old, new)
    assert [n for n, _ in start] == ["b"]
    assert stop == []


def test_disabled_connector_stops():
    old = _config(imap={"a": _imap(), "b": _imap()})
    new = _config(imap={"a": _imap(), "b": _imap(enable=False)})
    start, stop = diff_mailbox_configs(old, new)
    assert [n for n, _ in stop] == ["b"]
    assert start == []


def test_removed_connector_stops():
    old = _config(imap={"a": _imap(), "b": _imap()})
    new = _config(imap={"a": _imap()})
    start, stop = diff_mailbox_configs(old, new)
    assert [n for n, _ in stop] == ["b"]


def test_changed_connection_restarts():
    old = _config(imap={"a": _imap(host="old")})
    new = _config(imap={"a": _imap(host="new")})
    start, stop = diff_mailbox_configs(old, new)
    assert [n for n, _ in start] == ["a"]  # new started
    assert [n for n, _ in stop] == ["a"]   # old stopped (replace)


def test_unchanged_enabled_is_noop():
    old = _config(imap={"a": _imap()})
    new = _config(imap={"a": _imap()})
    start, stop = diff_mailbox_configs(old, new)
    assert start == [] and stop == []


def test_spans_imap_and_imaps_sections():
    old = _config(imap={"a": _imap()})
    new = _config(imap={"a": _imap()}, imaps={"s": _imap(use_ssl=True)})
    start, stop = diff_mailbox_configs(old, new)
    assert [n for n, _ in start] == ["s"]


class _FakeMailbox:
    def __init__(self, config, logger=None, tmp_path=None):
        self.config = config
        self.logged_in = False

    def login(self):
        self.logged_in = True

    def logout(self):
        self.logged_in = False


def test_apply_diff_stops_old_starts_new(monkeypatch):
    monkeypatch.setattr(
        "classes.services.mailbox_service.Mailbox", _FakeMailbox,
    )
    old_cfg = _imap(host="old")
    current = _FakeMailbox(old_cfg)
    to_start = [("a", _imap(host="new"))]
    to_stop = [("a", old_cfg)]

    result = apply_mailbox_diff(
        [current], to_start, to_stop, pathlib.Path("/tmp"), logging.getLogger("t"),
    )

    assert current not in result          # old stopped
    assert len(result) == 1
    assert result[0].config.host == "new" and result[0].logged_in  # new logged in

