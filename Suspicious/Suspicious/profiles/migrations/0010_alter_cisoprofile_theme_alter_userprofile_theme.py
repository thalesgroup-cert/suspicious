from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('profiles', '0009_alter_cisoprofile_theme_alter_userprofile_theme'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cisoprofile',
            name='theme',
            field=models.CharField(choices=[('midnight', 'Midnight'), ('graphite', 'Graphite'), ('slate', 'Slate'), ('light', 'Light'), ('paper', 'Paper'), ('high_contrast', 'High contrast'), ('sunrise', 'Sunrise'), ('valentine', 'Valentine'), ('cyber', 'Cyber'), ('the_one', 'The One'), ('metal', 'Metal'), ('future', 'Future'), ('summer', 'Summer'), ('winter', 'Winter'), ('spring', 'Spring'), ('autumn', 'Autumn'), ('renee', 'Renée')], default='light', max_length=50),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='theme',
            field=models.CharField(choices=[('midnight', 'Midnight'), ('graphite', 'Graphite'), ('slate', 'Slate'), ('light', 'Light'), ('paper', 'Paper'), ('high_contrast', 'High contrast'), ('sunrise', 'Sunrise'), ('valentine', 'Valentine'), ('cyber', 'Cyber'), ('the_one', 'The One'), ('metal', 'Metal'), ('future', 'Future'), ('summer', 'Summer'), ('winter', 'Winter'), ('spring', 'Spring'), ('autumn', 'Autumn'), ('renee', 'Renée')], default='light', max_length=50),
        ),
    ]
