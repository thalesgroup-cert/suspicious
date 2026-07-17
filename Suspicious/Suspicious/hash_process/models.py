from django.db import models

from common.model_mixins import AllowListableMixin


class Hash(AllowListableMixin, models.Model):
    id = models.AutoField(primary_key=True)
    value = models.CharField(max_length=255)
    ioc_score = models.FloatField(default=5)
    ioc_confidence = models.FloatField(default=0)
    ioc_level = models.CharField(max_length=20, default='info')
    hashtype = models.CharField(max_length=50, default='sha256 hash')
    times_sent = models.PositiveIntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.value