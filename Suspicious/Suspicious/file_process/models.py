from django.db import models
import uuid
from hash_process.models import Hash

from common.model_mixins import AllowListableMixin


class File(AllowListableMixin, models.Model):
    allowlist_score_fields = ("file_score", "file_confidence", "file_level")
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    linked_hash = models.ForeignKey(Hash, on_delete=models.CASCADE, related_name='file')
    file_path = models.FileField(upload_to='files/')
    file_score = models.FloatField(default=5)
    file_confidence = models.FloatField(default=0)
    file_level = models.CharField(max_length=20, default='info')
    tmp_path = models.TextField()
    filetype = models.CharField(max_length=255, default='unknown filetype')
    size = models.PositiveIntegerField(default=0)
    other_names = models.TextField()
    times_sent = models.PositiveIntegerField(default=0)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.file_path.name

class HashFromFile(models.Model):
    id = models.AutoField(primary_key=True)
    hash = models.ForeignKey(Hash, on_delete=models.CASCADE, related_name='hash_files')
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='hash_files')
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.hash.value