from django.db import models
from url_process.models import URL
from email_process.models import MailAddress
from django.utils.translation import gettext_lazy as _

class Domain(models.Model):
    id = models.AutoField(primary_key=True)
    ioc_score = models.FloatField(default=5)
    ioc_confidence = models.FloatField(default=0)
    ioc_level = models.CharField(max_length=20, default='info')
    value = models.TextField()
    category = models.CharField(max_length=50, default='unknown category')
    linked_urls = models.ManyToManyField(URL, through='DomainInIocs', related_name='domains')
    linked_mail_addresses = models.ManyToManyField(MailAddress, through='DomainInIocs', related_name='domains')
    times_sent = models.PositiveIntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.value
    
class DomainInIocs(models.Model):
    id = models.AutoField(primary_key=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='domain_iocs')
    url = models.ForeignKey(URL, on_delete=models.CASCADE, related_name='domain_iocs', null=True, blank=True)
    mail_address = models.ForeignKey(MailAddress, on_delete=models.CASCADE, related_name='domain_iocs', null=True, blank=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        if self.url:
            return f"{self.domain.value} - {self.url.address}"
        elif self.mail_address:
            return f"{self.domain.value} - {self.mail_address.address}"
        else:
            return self.domain.value
    