from django.db import migrations


def backfill(apps, schema_editor):
    Case = apps.get_model("case_handler", "Case")
    CaseAnalyzerJob = apps.get_model("cortex_job", "CaseAnalyzerJob")
    PENDING = ("Waiting", "InProgress")  # mirror CaseAnalyzerJob.PENDING_STATUSES
    for case in Case.objects.all().iterator(chunk_size=200):
        if case.status == "Done":
            case.lifecycle_state = "FINALIZED"
            case.finalized_at = case.finalized_at or case.last_update
        elif case.status == "Challenged":
            case.lifecycle_state = "CONTESTED"
        else:  # On Going / To Do
            has_pending = CaseAnalyzerJob.objects.filter(
                case=case, status__in=PENDING
            ).exists()
            case.lifecycle_state = "ANALYZING" if has_pending else "CREATED"
        case.save(update_fields=["lifecycle_state", "finalized_at"])


class Migration(migrations.Migration):
    dependencies = [
        ("case_handler", "0014_case_lifecycle_state"),
        ("cortex_job", "0010_backfill_caseanalyzerjob"),
    ]
    operations = [migrations.RunPython(backfill, migrations.RunPython.noop)]
