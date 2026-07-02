# Generated migration file for adding tour_completed field to profiles

from django.db import migrations, models
from django.utils.translation import gettext_lazy as _


class Migration(migrations.Migration):

    dependencies = [
        ('profiles', '0011_userprofile_avatar_cisoprofile_avatar'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='tour_completed',
            field=models.BooleanField(
                default=False,
                help_text=_('True once the user has seen the first-connection guided tour.'),
                verbose_name=_('Guided tour completed'),
            ),
        ),
        migrations.AddField(
            model_name='cisoprofile',
            name='tour_completed',
            field=models.BooleanField(
                default=False,
                help_text=_('True once the user has seen the first-connection guided tour.'),
                verbose_name=_('Guided tour completed'),
            ),
        ),
    ]
