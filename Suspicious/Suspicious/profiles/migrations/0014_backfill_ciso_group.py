from django.db import migrations


def grant_ciso_group(apps, schema_editor):
    CISOProfile = apps.get_model("profiles", "CISOProfile")
    Group = apps.get_model("auth", "Group")
    group, _ = Group.objects.get_or_create(name="CISO")
    for profile in CISOProfile.objects.select_related("user").iterator():
        profile.user.groups.add(group)


def noop(apps, schema_editor):
    # Deliberately not removing users from the CISO group on reverse — a
    # profile deleted after this migration would already have been handled
    # by the post_delete signal, and admins may have granted the group by
    # other means.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("profiles", "0013_cisoprofile_sidebar_pinned_and_more"),
    ]

    operations = [
        migrations.RunPython(grant_ciso_group, noop),
    ]
