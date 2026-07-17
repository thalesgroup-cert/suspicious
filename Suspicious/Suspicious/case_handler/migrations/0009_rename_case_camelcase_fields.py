"""
Rename Case fields from camelCase to snake_case (M4).

Pure RenameField migration — no data change, no schema rebuild.
MariaDB ALTER TABLE for column rename is fast on large tables because
no row rewrite happens.

Coordinated with frontend: suspicious-ui/src/features/investigation/api.ts
must read the new snake_case keys after this migration applies. Backend
serializers expose the new keys as part of the same deploy.
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("case_handler", "0008_case_is_challengeable"),
    ]

    operations = [
        migrations.RenameField(
            model_name="case",
            old_name="finalScore",
            new_name="final_score",
        ),
        migrations.RenameField(
            model_name="case",
            old_name="finalConfidence",
            new_name="final_confidence",
        ),
        migrations.RenameField(
            model_name="case",
            old_name="resultsAI",
            new_name="results_ai",
        ),
        migrations.RenameField(
            model_name="case",
            old_name="scoreAI",
            new_name="score_ai",
        ),
        migrations.RenameField(
            model_name="case",
            old_name="confidenceAI",
            new_name="confidence_ai",
        ),
        migrations.RenameField(
            model_name="case",
            old_name="categoryAI",
            new_name="category_ai",
        ),
    ]
