from __future__ import annotations

from rest_framework import serializers

from case_handler.models import CaseComment


class CaseCommentSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source="author.email", read_only=True)
    body = serializers.CharField(trim_whitespace=True, allow_blank=False, max_length=4000)

    class Meta:
        model = CaseComment
        fields = ["id", "author_email", "body", "is_internal", "created_at"]
        read_only_fields = ["id", "author_email", "is_internal", "created_at"]
