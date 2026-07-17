# M3 — Consolidate FileInCases / HashInCases / UrlInCases / IpInCases /
# MailInCases into a single CaseArtifact model.
#
# Order of operations:
#   1. Create CaseArtifact (no constraints yet — data backfill must be
#      free to insert duplicates we then dedupe).
#   2. RunPython: copy every (case, artifact) pair from each old M2M
#      table into CaseArtifact.
#   3. Tear down the old M2M relations and models.
#   4. Add the per-artifact partial unique constraints.

import django.db.models.deletion
from django.db import migrations, models


def copy_case_artifacts(apps, schema_editor):
    CaseArtifact = apps.get_model('case_handler', 'CaseArtifact')

    spec = [
        # (model_name, fk_field, m2m_field, artifact_type)
        ('FileInCases',  'file',            'case',              'file'),
        ('HashInCases',  'hash',            'case',              'hash'),
        ('UrlInCases',   'url',             'case',              'url'),
        ('IpInCases',    'ip',              'case',              'ip'),
        ('MailInCases',  'associated_mail', 'associated_cases',  'mail'),
    ]

    new_fk_for_artifact_type = {
        'file': 'file_id', 'hash': 'hash_id', 'url': 'url_id',
        'ip': 'ip_id', 'mail': 'mail_id',
    }

    seen = set()  # (case_id, artifact_type, fk_id) — emulates the partial
                  # unique constraints which are added AFTER this step

    for model_name, fk_field, m2m_field, artifact_type in spec:
        Model = apps.get_model('case_handler', model_name)
        new_fk = new_fk_for_artifact_type[artifact_type]
        for row in Model.objects.all().iterator():
            artifact_pk = getattr(row, f"{fk_field}_id")
            if artifact_pk is None:
                continue
            for case in getattr(row, m2m_field).all().iterator():
                key = (case.pk, artifact_type, artifact_pk)
                if key in seen:
                    continue
                seen.add(key)
                CaseArtifact.objects.create(
                    case_id=case.pk,
                    artifact_type=artifact_type,
                    **{new_fk: artifact_pk},
                )


def reverse_copy_case_artifacts(apps, schema_editor):
    # Reverse direction is intentionally a no-op: the old per-type models
    # have been deleted by the time this migration is unwound, and there
    # is no production read-path to restore.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('case_handler', '0011_alter_case_challenged_result_alter_case_confidence_and_more'),
        ('file_process', '0002_alter_file_file_level_alter_file_file_score'),
        ('hash_process', '0002_alter_hash_ioc_level_alter_hash_ioc_score'),
        ('ip_process', '0002_alter_ip_ioc_level_alter_ip_ioc_score'),
        ('mail_feeder', '0015_remove_mailbody_mail_feeder_fuzzy_h_dfe882_idx_and_more'),
        ('url_process', '0003_alter_url_ioc_level_alter_url_ioc_score'),
    ]

    operations = [
        # 1. Create the new model first so the data migration can target it.
        migrations.CreateModel(
            name='CaseArtifact',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('artifact_type', models.CharField(choices=[('file', 'File'), ('hash', 'Hash'), ('url', 'URL'), ('ip', 'IP'), ('mail', 'Mail')], db_index=True, max_length=10)),
                ('creation_date', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('last_update', models.DateTimeField(auto_now=True)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='case_artifacts', to='case_handler.case')),
                ('file', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='case_artifacts', to='file_process.file')),
                ('hash', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='case_artifacts', to='hash_process.hash')),
                ('ip', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='case_artifacts', to='ip_process.ip')),
                ('mail', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='case_artifacts', to='mail_feeder.mail')),
                ('url', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='case_artifacts', to='url_process.url')),
            ],
            options={
                'ordering': ['-creation_date'],
            },
        ),

        # 2. Backfill from the legacy per-type M2M tables.
        migrations.RunPython(copy_case_artifacts, reverse_copy_case_artifacts),

        # 3. Tear down the legacy schema.
        migrations.RemoveField(model_name='hashincases', name='case'),
        migrations.RemoveField(model_name='hashincases', name='hash'),
        migrations.RemoveField(model_name='ipincases', name='case'),
        migrations.RemoveField(model_name='ipincases', name='ip'),
        migrations.RemoveField(model_name='mailincases', name='associated_cases'),
        migrations.RemoveField(model_name='mailincases', name='associated_mail'),
        migrations.RemoveField(model_name='urlincases', name='case'),
        migrations.RemoveField(model_name='urlincases', name='url'),
        migrations.DeleteModel(name='FileInCases'),
        migrations.DeleteModel(name='HashInCases'),
        migrations.DeleteModel(name='IpInCases'),
        migrations.DeleteModel(name='MailInCases'),
        migrations.DeleteModel(name='UrlInCases'),

        # 4. Apply per-artifact partial unique constraints last so the
        #    backfill can run without tripping them mid-flight.
        migrations.AddConstraint(
            model_name='caseartifact',
            constraint=models.UniqueConstraint(condition=models.Q(('file__isnull', False)), fields=('case', 'artifact_type', 'file'), name='caseartifact_unique_file'),
        ),
        migrations.AddConstraint(
            model_name='caseartifact',
            constraint=models.UniqueConstraint(condition=models.Q(('hash__isnull', False)), fields=('case', 'artifact_type', 'hash'), name='caseartifact_unique_hash'),
        ),
        migrations.AddConstraint(
            model_name='caseartifact',
            constraint=models.UniqueConstraint(condition=models.Q(('url__isnull', False)), fields=('case', 'artifact_type', 'url'), name='caseartifact_unique_url'),
        ),
        migrations.AddConstraint(
            model_name='caseartifact',
            constraint=models.UniqueConstraint(condition=models.Q(('ip__isnull', False)), fields=('case', 'artifact_type', 'ip'), name='caseartifact_unique_ip'),
        ),
        migrations.AddConstraint(
            model_name='caseartifact',
            constraint=models.UniqueConstraint(condition=models.Q(('mail__isnull', False)), fields=('case', 'artifact_type', 'mail'), name='caseartifact_unique_mail'),
        ),
    ]
