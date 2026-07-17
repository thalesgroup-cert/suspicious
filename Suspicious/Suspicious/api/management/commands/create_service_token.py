"""Provision a scoped service principal + Knox token for service-to-service
config reads. Usage: `python manage.py create_service_token feeder`.

Prints the token to stdout — capture it into the consuming service's env
(e.g. FEEDER_API_TOKEN). Re-running reuses the user and issues a fresh token.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand, CommandError

from knox.models import AuthToken

from settings.config import SCOPE_SECTIONS

User = get_user_model()


class Command(BaseCommand):
    help = "Create a scoped service user + Knox token for config reads."

    def add_arguments(self, parser):
        parser.add_argument("scope", help="config scope, e.g. 'feeder'")

    def handle(self, *args, **options):
        scope = options["scope"]
        if scope not in SCOPE_SECTIONS or scope == "shared":
            raise CommandError(
                f"scope must be one of {sorted(set(SCOPE_SECTIONS) - {'shared'})}"
            )
        user, _ = User.objects.get_or_create(
            username=f"svc-{scope}",
            defaults={"is_active": True, "is_staff": False},
        )
        group, _ = Group.objects.get_or_create(name=scope)
        user.groups.add(group)
        _, token = AuthToken.objects.create(user, expiry=None)
        self.stdout.write(token)
