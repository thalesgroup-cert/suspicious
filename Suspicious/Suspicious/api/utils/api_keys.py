from django.utils import timezone
from knox.models import AuthToken


def generate_api_key(user, expiration_days: int):
    """
    Create a Knox token for a user and return:
    - raw token string (shown once)
    - AuthToken instance
    """
    expiry = timezone.timedelta(days=expiration_days)
    token_instance, raw_key = AuthToken.objects.create(user=user, expiry=expiry)
    return raw_key, token_instance