from django.db import models
from django.utils.translation import gettext_lazy as _

class IP(models.Model):
    id = models.AutoField(primary_key=True)
    address = models.CharField(max_length=15)
    ioc_score = models.FloatField(default=5)
    ioc_confidence = models.FloatField(default=0)
    ioc_level = models.CharField(max_length=20, default='info')
    times_sent = models.PositiveIntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.address
    