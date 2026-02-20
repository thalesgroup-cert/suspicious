from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("case_handler", "0006_alter_case_challenged_result_alter_case_results"),
    ]

    operations = [
        migrations.CreateModel(
            name="CaseChallengeToken",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("token_hash", models.CharField(db_index=True, max_length=64, unique=True)),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("used_at", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="challenge_tokens", to="case_handler.case")),
            ],
            options={
                "indexes": [
                    models.Index(fields=["case", "expires_at"], name="cct_case_expires_idx"),
                    models.Index(fields=["case", "used_at"], name="cct_case_used_idx"),
                ],
            },
        ),
    ]
