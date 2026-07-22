"""Pure-logic tests for mail_header_analysis.py — stdlib `email` only, no
cortexutils/network dependency needed, so these run without the Docker image."""
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
