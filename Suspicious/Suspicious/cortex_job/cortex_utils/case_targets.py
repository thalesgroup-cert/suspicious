"""Shared artifact-walk for an existing Case — used both to build the
AnalyzerReport query (investigations/submissions detail views) and to build
Cortex dispatch intents (redo-analysis)."""
from __future__ import annotations

from django.db import models


def collect_case_targets(case) -> list[tuple[models.Model, str]]:
    """Walk case.fileOrMail / case.nonFileIocs and return every distinct
    (instance, data_type) artifact linked to this case.

    De-duplicated by (data_type, pk): the same URL/IP/hash/domain/mail
    address can be referenced by more than one MailArtifact row on the
    same mail, and callers that dispatch analyzers per target (unlike a
    SQL `IN` filter, which silently absorbs list duplicates) must not see
    the same artifact twice.
    """
    seen: dict[tuple[str, int], models.Model] = {}

    def _add(instance, data_type: str) -> None:
        if instance is None or instance.pk is None:
            return
        seen[(data_type, instance.pk)] = instance

    file_or_mail = getattr(case, "fileOrMail", None)
    non_file_iocs = getattr(case, "nonFileIocs", None)

    if case.fileOrMail_id and file_or_mail:
        if file_or_mail.file_id:
            _add(file_or_mail.file, "file")

        if file_or_mail.mail_id and getattr(file_or_mail, "mail", None):
            mail = file_or_mail.mail

            if mail.mail_body_id:
                _add(mail.mail_body, "mail_body")
            if mail.mail_header_id:
                _add(mail.mail_header, "mail_header")

            for attachment in mail.mail_attachments.exclude(file_id__isnull=True).select_related("file"):
                _add(attachment.file, "file")

            for artifact in mail.mail_artifacts.select_related(
                "artifactIsUrl", "artifactIsUrl__url",
                "artifactIsIp", "artifactIsIp__ip",
                "artifactIsHash", "artifactIsHash__hash",
                "artifactIsDomain", "artifactIsDomain__domain",
                "artifactIsMailAddress", "artifactIsMailAddress__mail_address",
            ):
                if artifact.artifactIsUrl_id and artifact.artifactIsUrl and artifact.artifactIsUrl.url_id:
                    url = artifact.artifactIsUrl.url
                    _add(url, "url")
                    if getattr(url, "analyzed_url_id", None):
                        _add(url.analyzed_url, "url")
                if artifact.artifactIsIp_id and artifact.artifactIsIp and artifact.artifactIsIp.ip_id:
                    _add(artifact.artifactIsIp.ip, "ip")
                if artifact.artifactIsHash_id and artifact.artifactIsHash and artifact.artifactIsHash.hash_id:
                    _add(artifact.artifactIsHash.hash, "hash")
                if artifact.artifactIsDomain_id and artifact.artifactIsDomain and artifact.artifactIsDomain.domain_id:
                    _add(artifact.artifactIsDomain.domain, "domain")
                if (
                    artifact.artifactIsMailAddress_id
                    and artifact.artifactIsMailAddress
                    and artifact.artifactIsMailAddress.mail_address_id
                ):
                    _add(artifact.artifactIsMailAddress.mail_address, "mail")

    if case.nonFileIocs_id and non_file_iocs:
        if non_file_iocs.url_id:
            url = non_file_iocs.url
            _add(url, "url")
            if getattr(url, "analyzed_url_id", None):
                _add(url.analyzed_url, "url")
        if non_file_iocs.ip_id:
            _add(non_file_iocs.ip, "ip")
        if non_file_iocs.hash_id:
            _add(non_file_iocs.hash, "hash")

    return [(instance, data_type) for (data_type, _pk), instance in seen.items()]
