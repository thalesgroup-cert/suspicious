"""An in-memory stand-in for imaplib.IMAP4, enough for the review-folder reader (Plan D)."""
from __future__ import annotations

import re


class FakeImap:
    """folders: name -> {"uidvalidity": int, "messages": {uid: bytes}}.

    `fetch_override` maps a uid to the raw data list `uid("FETCH")` returns for it, to mimic odd
    server answers. `search_extra` adds UIDs to every SEARCH answer (servers answer "n:*" with the
    last existing UID even when none is newer). `sizes` overrides the RFC822.SIZE a uid reports.
    `errors` maps "SELECT", "SEARCH", "SIZE" or a uid (its BODY fetch) to an exception to raise
    once that command is recorded. Every call lands in `commands`.
    """

    def __init__(self, folders=None, *, fetch_override=None, search_extra=(), sizes=None, errors=None):
        self.folders = folders or {}
        self.sizes = sizes or {}
        self.errors = errors or {}
        self.fetch_override = fetch_override or {}
        self.search_extra = tuple(search_extra)
        self.commands: list[tuple] = []
        self.selected = None
        self.untagged_responses: dict[str, list] = {}

    def select(self, mailbox="INBOX", readonly=False):
        self.commands.append(("SELECT", mailbox, readonly))
        if "SELECT" in self.errors:
            raise self.errors["SELECT"]
        self.untagged_responses = {}  # imaplib clears them at select
        name = mailbox
        if len(name) >= 2 and name[0] == name[-1] == '"':
            name = re.sub(r'\\(.)', r"\1", name[1:-1])  # IMAP quoted string
        folder = self.folders.get(name)
        if folder is None:
            self.selected = None
            return "NO", [b"[NONEXISTENT] Unknown Mailbox"]
        self.selected = folder
        self.untagged_responses["UIDVALIDITY"] = [str(folder["uidvalidity"]).encode()]
        if readonly:
            self.untagged_responses["READ-ONLY"] = [b""]
        return "OK", [str(len(folder["messages"])).encode()]

    def response(self, code):
        # Same as imaplib.IMAP4.response: pop the untagged data, (code, [None]) when absent.
        return code, self.untagged_responses.pop(code.upper(), [None])

    def uid(self, command, *args):
        command = command.upper()
        self.commands.append(("UID", command, *args))
        if self.selected is None:
            raise AssertionError("uid() called with no folder selected")
        messages = self.selected["messages"]
        if command == "SEARCH":
            # args: (None, "UID", "n:*")
            if "SEARCH" in self.errors:
                raise self.errors["SEARCH"]
            low = int(args[-1].split(":", 1)[0])
            hits = sorted({u for u in messages if u >= low} | set(self.search_extra))
            return "OK", [" ".join(str(u) for u in hits).encode()]
        if command == "FETCH" and args[1] == "(RFC822.SIZE)":
            if "SIZE" in self.errors:
                raise self.errors["SIZE"]
            uids = [int(u) for u in args[0].split(",")]
            return "OK", [
                f"{n} (UID {u} RFC822.SIZE {self.sizes.get(u, len(messages[u]))})".encode()
                for n, u in enumerate(uids, 1) if u in messages
            ]
        if command == "FETCH":
            uid, spec = int(args[0]), args[1]
            if uid in self.errors:
                raise self.errors[uid]
            if spec != "(BODY.PEEK[])":
                raise AssertionError(f"unexpected fetch spec {spec}")
            if uid in self.fetch_override:
                return "OK", self.fetch_override[uid]
            if uid not in messages:
                return "OK", [None]
            raw = messages[uid]
            return "OK", [(f"{uid} (UID {uid} BODY[] {{{len(raw)}}}".encode(), raw), b")"]
        raise AssertionError(f"unexpected UID command {command}")

    def logout(self):
        self.commands.append(("LOGOUT",))
        return "BYE", [b"logging out"]
