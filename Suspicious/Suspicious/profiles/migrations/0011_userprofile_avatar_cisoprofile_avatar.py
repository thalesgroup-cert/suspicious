# Generated migration file for adding avatar field to profiles

from django.db import migrations, models
from django.utils.translation import gettext_lazy as _


class Migration(migrations.Migration):

    dependencies = [
        ('profiles', '0010_alter_cisoprofile_theme_alter_userprofile_theme'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='avatar',
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text=_('DiceBear avatar config. Structure: {style: \'<dicebear-style>\', seed: \'<string>\'}. Empty means fall back to initials.'),
                verbose_name=_('Avatar'),
            ),
        ),
        migrations.AddField(
            model_name='cisoprofile',
            name='avatar',
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text=_('DiceBear avatar config. Structure: {style: \'<dicebear-style>\', seed: \'<string>\'}. Empty means fall back to initials.'),
                verbose_name=_('Avatar'),
            ),
        ),
    ]
