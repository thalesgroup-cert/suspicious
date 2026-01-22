from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import User
from knox.models import AuthToken


class APIKey(models.Model):
    """
    Manages creation, modification, and deletion of user API keys.
    """
    auth_token = models.OneToOneField(AuthToken, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"API Key for {self.auth_token.user.username}"

    class Meta:
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        app_label = 'profiles'

class Theme(models.TextChoices):
    """
    Enumeration of possible suspicious theme.
    """
    LIGHT = 'light', _('Light')
    DARK = 'dark', _('Dark')
    DEFAULT = 'default', _('Default')

class UserProfile(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    function = models.CharField(max_length=200)
    gbu = models.CharField(max_length=200)
    country = models.CharField(max_length=200)
    region = models.CharField(max_length=200)
    wants_acknowledgement = models.BooleanField(default=True)
    wants_results = models.BooleanField(default=True)
    theme = models.CharField(max_length=10, choices=Theme.choices, default=Theme.DEFAULT)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.user.username

class CISOProfile(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    function = models.CharField(max_length=200)
    gbu = models.CharField(max_length=200)
    country = models.CharField(max_length=200)
    region = models.CharField(max_length=200)
    scope = models.CharField(max_length=200, default='Not defined')
    wants_acknowledgement = models.BooleanField(default=True)
    wants_results = models.BooleanField(default=True)
    theme = models.CharField(max_length=10, choices=Theme.choices, default=Theme.DEFAULT)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.user.username