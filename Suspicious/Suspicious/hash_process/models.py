from django.db import models
from django.utils.translation import gettext_lazy as _

class Hash(models.Model):
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

    def update_allow_listed(self):
        """
        Mark this Hash instance as allow_listed (safe).
        """
        self.ioc_score = 0
        self.ioc_confidence = 100
        self.ioc_level = "SAFE-ALLOW_LISTED"
        self.save(update_fields=["ioc_score", "ioc_confidence", "ioc_level"])