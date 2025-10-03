from django.conf import settings
from django.db import models
from domain_process.models import Domain
from hash_process.models import Hash
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password



class Mailbox(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, unique=True)
    username = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=256)
    server = models.CharField(max_length=50)
    port = models.IntegerField()
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name
    

class EmailFeederState(models.Model):
    is_running = models.BooleanField(default=False)  # Store the state (ON/OFF)
    updated_at = models.DateTimeField(auto_now=True)  # Store the last update time

    def __str__(self):
        return f"Email Feeder is {'ON' if self.is_running else 'OFF'}"

class AllowListDomain(models.Model):
    id = models.AutoField(primary_key=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='allow_lists', null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.domain.value
    
class DenyListDomain(models.Model):
    id = models.AutoField(primary_key=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='deny_lists', null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.domain.value

class CampaignDomainAllowList(models.Model):
    id = models.AutoField(primary_key=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='campaign_allow_lists', null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.domain.value

class AllowListFile(models.Model):
    id = models.AutoField(primary_key=True)
    linked_file_hash = models.ForeignKey(Hash, on_delete=models.CASCADE, related_name='allow_lists', null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.linked_file_hash.value
    
class DenyListFile(models.Model):
    id = models.AutoField(primary_key=True)
    linked_file_hash = models.ForeignKey(Hash, on_delete=models.CASCADE, related_name='deny_lists', null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.linked_file_hash.value
    
class AllowListFiletype(models.Model):
    id = models.AutoField(primary_key=True)
    filetype = models.CharField(max_length=200)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.filetype