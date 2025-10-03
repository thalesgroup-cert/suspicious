from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

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