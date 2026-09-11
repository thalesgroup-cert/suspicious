"""The observable string an AnalyzerReport is about, resolved from its
non-null FK. Shared by the enrichment registry and the investigation
serializer (get_target)."""
from __future__ import annotations

from typing import Optional


def analyzer_report_target_value(report) -> Optional[str]:
    if report.url_id:
        return getattr(report.url, "address", None)
    if report.domain_id:
        return getattr(report.domain, "value", None)
    if report.mail_id:
        return getattr(report.mail, "address", None)
    if report.hash_id:
        return getattr(report.hash, "value", None)
    if report.file_id:
        f = getattr(report.file, "file_path", None)
        return getattr(f, "name", None) or None
    if report.ip_id:
        return getattr(report.ip, "address", None)
    if report.mail_body_id:
        return getattr(report.mail_body, "fuzzy_hash", None)
    if report.mail_header_id:
        return getattr(report.mail_header, "fuzzy_hash", None)
    return None
