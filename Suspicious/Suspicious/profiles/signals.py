"""Keep the ``CISO`` auth group in sync with CISOProfile rows.

Every RBAC check (api IsInvestigator, ProtectedRoute, home, dashboard)
keys off membership in the ``CISO`` group, but the CISOProfile creation
paths (LDAP sync, profiles_utils.ciso.process_cisos, admin import) only
ever create the profile. This signal is the single chokepoint that
grants — and revokes — the group alongside the profile.
"""
import logging

from django.contrib.auth.models import Group
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from profiles.models import CISOProfile

logger = logging.getLogger("profiles")

CISO_GROUP = "CISO"


@receiver(post_save, sender=CISOProfile, dispatch_uid="ciso_profile_grant_group")
def grant_ciso_group(sender, instance, created, **kwargs):
    if not created:
        return
    group, _ = Group.objects.get_or_create(name=CISO_GROUP)
    instance.user.groups.add(group)
    logger.info("Added user %r to the %s group (CISOProfile created).",
                instance.user.username, CISO_GROUP)


@receiver(post_delete, sender=CISOProfile, dispatch_uid="ciso_profile_revoke_group")
def revoke_ciso_group(sender, instance, **kwargs):
    try:
        group = Group.objects.get(name=CISO_GROUP)
    except Group.DoesNotExist:
        return
    instance.user.groups.remove(group)
    logger.info("Removed user %r from the %s group (CISOProfile deleted).",
                instance.user.username, CISO_GROUP)
