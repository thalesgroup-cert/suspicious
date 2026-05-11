from django.db import migrations
from django.db.models import Q


def backfill(apps, schema_editor):
    Case = apps.get_model("case_handler", "Case")
    AnalyzerReport = apps.get_model("cortex_job", "AnalyzerReport")
    CaseAnalyzerJob = apps.get_model("cortex_job", "CaseAnalyzerJob")

    cases = Case.objects.exclude(status="Done").iterator(chunk_size=100)
    rows = []
    for case in cases:
        q = Q()
        fom = getattr(case, "fileOrMail", None)
        if fom:
            if fom.file_id:
                q |= Q(file_id=fom.file_id)
            mail = getattr(fom, "mail", None)
            if mail:
                if mail.mail_body_id:
                    q |= Q(mail_body_id=mail.mail_body_id)
                if mail.mail_header_id:
                    q |= Q(mail_header_id=mail.mail_header_id)
                for att in mail.mail_attachments.all():
                    if att.file_id:
                        q |= Q(file_id=att.file_id)
                for art in mail.mail_artifacts.all():
                    if art.artifactIsIp_id:
                        q |= Q(ip=art.artifactIsIp.ip)
                    if art.artifactIsUrl_id:
                        q |= Q(url=art.artifactIsUrl.url)
                    if art.artifactIsHash_id:
                        q |= Q(hash=art.artifactIsHash.hash)
                    if art.artifactIsDomain_id:
                        q |= Q(domain=art.artifactIsDomain.domain)
                    if art.artifactIsMailAddress_id:
                        q |= Q(mail=art.artifactIsMailAddress.mail_address)
        nfi = getattr(case, "nonFileIocs", None)
        if nfi:
            for fk in ("url_id", "ip_id", "hash_id"):
                val = getattr(nfi, fk, None)
                if val:
                    q |= Q(**{fk: val})

        if not q.children:
            continue

        for ar in AnalyzerReport.objects.filter(q).exclude(status="Deleted"):
            rows.append(CaseAnalyzerJob(
                case_id=case.id,
                cortex_job_id=ar.cortex_job_id,
                analyzer_id=ar.analyzer_id,
                analyzer_report_id=ar.id,
                status=ar.status,
                created_at=ar.creation_date,
                completed_at=None if ar.status in ("Waiting", "InProgress") else ar.last_update,
            ))
            if len(rows) >= 1000:
                CaseAnalyzerJob.objects.bulk_create(rows, ignore_conflicts=True)
                rows = []
    if rows:
        CaseAnalyzerJob.objects.bulk_create(rows, ignore_conflicts=True)


def reverse(apps, schema_editor):
    apps.get_model("cortex_job", "CaseAnalyzerJob").objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [
        ("cortex_job", "0009_drop_redundant_caj_indexes"),
    ]
    operations = [migrations.RunPython(backfill, reverse)]
