import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

# Deleting a user used to delete every list entry they added, with no ListChangeLog row.
# Entries now outlive the account and just lose their author.
_MODELS = (
    "allowlistdomain", "allowlistip", "denylistdomain",
    "campaigndomainallowlist", "allowlistfile", "allowlistfiletype",
)


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("settings", "0013_listchangelog"),
    ]

    operations = [
        migrations.AlterField(
            model_name=name,
            name="user",
            field=models.ForeignKey(
                null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL,
            ),
        )
        for name in _MODELS
    ]
