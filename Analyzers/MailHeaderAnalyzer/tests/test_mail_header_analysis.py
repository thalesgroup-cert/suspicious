"""Pure-logic tests for mail_header_analysis.py — stdlib `email` only, no
cortexutils/network dependency needed, so these run without the Docker image."""
import email
import email.policy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mail_header_analysis as mha  # noqa: E402


def _headers(*lines):
    return "\n".join(lines) + "\n"


def test_parse_auth_results_all_pass():
    msg = mha.parse_headers(_headers(
        "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=a.com; "
        "dkim=pass header.d=a.com; dmarc=pass"
    ))
    assert mha.parse_auth_results(msg) == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_parse_auth_results_missing_header_is_none():
    msg = mha.parse_headers(_headers("Subject: hi"))
    assert mha.parse_auth_results(msg) == {"spf": "none", "dkim": "none", "dmarc": "none"}


def test_parse_auth_results_mixed_across_multiple_headers_keeps_worst():
    msg = mha.parse_headers(_headers(
        "Authentication-Results: mx1.example.com; spf=pass; dkim=none",
        "Authentication-Results: mx2.example.com; spf=fail; dkim=pass; dmarc=fail",
    ))
    result = mha.parse_auth_results(msg)
    assert result["spf"] == "fail"
    assert result["dkim"] == "none"
    assert result["dmarc"] == "fail"


def test_get_domain_extracts_lowercased_domain():
    assert mha.get_domain("Alice <Alice@Example.COM>") == "example.com"


def test_get_domain_returns_empty_for_unparseable():
    assert mha.get_domain("not an address") == ""


def test_check_domain_mismatch_flags_different_domains():
    msg = mha.parse_headers(_headers(
        "From: Billing <billing@legit-bank.com>",
        "Reply-To: attacker@evil.com",
    ))
    result = mha.check_domain_mismatch(msg, "Reply-To")
    assert result == {
        "present": True, "match": False,
        "from_domain": "legit-bank.com", "other_domain": "evil.com",
    }


def test_check_domain_mismatch_matching_domains():
    msg = mha.parse_headers(_headers(
        "From: Billing <billing@legit-bank.com>",
        "Reply-To: support@legit-bank.com",
    ))
    assert mha.check_domain_mismatch(msg, "Reply-To")["match"] is True


def test_check_domain_mismatch_absent_header():
    msg = mha.parse_headers(_headers("From: billing@legit-bank.com"))
    result = mha.check_domain_mismatch(msg, "Return-Path")
    assert result["present"] is False
    assert result["match"] is True


def test_display_name_spoofing_detected():
    msg = mha.parse_headers(_headers(
        'From: "billing@legit-bank.com" <attacker@evil.com>'
    ))
    result = mha.check_display_name_spoofing(msg)
    assert result["spoofed"] is True
    assert "billing@legit-bank.com" in result["embedded_addresses"]


def test_display_name_spoofing_not_flagged_when_no_embedded_address():
    msg = mha.parse_headers(_headers("From: Billing Team <billing@legit-bank.com>"))
    assert mha.check_display_name_spoofing(msg)["spoofed"] is False


def test_build_verdict_all_pass_and_matching_is_safe():
    report = {
        "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "reply_to": {"present": True, "match": True, "from_domain": "a.com", "other_domain": "a.com"},
        "return_path": {"present": True, "match": True, "from_domain": "a.com", "other_domain": "a.com"},
        "display_name_spoofing": {"spoofed": False, "display_name": "A", "embedded_addresses": []},
    }
    taxonomies = mha.build_verdict(report)
    levels = {t["predicate"]: t["level"] for t in taxonomies}
    assert levels["SPF"] == "safe"
    assert levels["DKIM"] == "safe"
    assert levels["DMARC"] == "safe"
    assert levels["ReplyToMatch"] == "safe"
    assert levels["ReturnPathMatch"] == "safe"
    assert levels["DisplayNameSpoofing"] == "safe"


def test_build_verdict_spoofing_is_malicious():
    report = {
        "auth_results": {"spf": "none", "dkim": "none", "dmarc": "none"},
        "reply_to": {"present": False, "match": True, "from_domain": "a.com", "other_domain": ""},
        "return_path": {"present": False, "match": True, "from_domain": "a.com", "other_domain": ""},
        "display_name_spoofing": {"spoofed": True, "display_name": "x", "embedded_addresses": ["billing@a.com"]},
    }
    taxonomies = mha.build_verdict(report)
    levels = {t["predicate"]: t["level"] for t in taxonomies}
    assert levels["DisplayNameSpoofing"] == "malicious"
    assert levels["SPF"] == "info"


def test_analyze_end_to_end():
    header_text = _headers(
        "From: \"Legit Bank\" <billing@legit-bank.com>",
        "Reply-To: attacker@evil.com",
        "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail",
    )
    report = mha.analyze(header_text)
    assert report["auth_results"]["spf"] == "fail"
    assert report["reply_to"]["match"] is False
    predicates = {t["predicate"] for t in report["taxonomies"]}
    assert {"SPF", "DKIM", "DMARC", "ReplyToMatch", "ReturnPathMatch", "DisplayNameSpoofing"} == predicates


def test_analyze_recovers_flattened_headers_with_no_real_linebreaks():
    """Outlook's "Internet headers" popup, copy-pasted, commonly hands back
    one long line instead of newline-separated headers. Without reflowing,
    message_from_string reads the whole blob as one header's value and
    every later header vanishes."""
    flattened = (
        "Received: from a.example (1.2.3.4) by b.example; Wed, 22 Jul 2026 18:26:54 +0200 "
        "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass "
        "From: Attacker <attacker@evil.com> "
        "Reply-To: attacker@evil.com"
    )
    report = mha.analyze(flattened)
    assert report["auth_results"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert report["reply_to"]["from_domain"] == "evil.com"


def test_get_domain_undoes_bracket_defanged_dots():
    """CERT analysts routinely defang IOCs ("evil[.]com") before sharing a
    header dump; parseaddr reads "[.]" as an RFC 5322 domain-literal and
    fails the whole address, so domain extraction must undo it first."""
    assert mha.get_domain("attacker@evil[.]com") == "evil.com"
    assert mha.get_domain("Attacker <attacker@evil[.]com>") == "evil.com"


def test_analyze_message_works_on_a_full_eml_not_just_bare_headers():
    """The .eml data-type entry point parses a full message (headers + body)
    via email.message_from_bytes — analyze_message must give the same result
    as the bare-header-block entry point since it only ever touches headers."""
    eml_bytes = (
        b'From: "Legit Bank" <billing@legit-bank.com>\r\n'
        b"Reply-To: attacker@evil.com\r\n"
        b"Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        b"Subject: Urgent action required\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Click here to verify your account.\r\n"
    )
    msg = email.message_from_bytes(eml_bytes, policy=email.policy.default)
    report = mha.analyze_message(msg)
    assert report["auth_results"] == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    assert report["reply_to"]["match"] is False
    assert report["reply_to"]["from_domain"] == "legit-bank.com"
