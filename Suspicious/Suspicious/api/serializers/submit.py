from rest_framework import serializers


class SubmitUrlSerializer(serializers.Serializer):
    url = serializers.URLField()
    context = serializers.CharField(required=False, allow_blank=True, allow_null=True)


class SubmitOtherSerializer(serializers.Serializer):
    value = serializers.CharField()
    context = serializers.CharField(required=False, allow_blank=True, allow_null=True)


class SubmitFileSerializer(serializers.Serializer):
    file = serializers.FileField()
    context = serializers.CharField(required=False, allow_blank=True, allow_null=True)


class SubmitConfigSerializer(serializers.Serializer):
    suspicious_email = serializers.EmailField()