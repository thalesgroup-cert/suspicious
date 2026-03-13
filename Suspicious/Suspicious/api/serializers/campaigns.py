from rest_framework import serializers


class CampaignClassificationCountsSerializer(serializers.Serializer):
    SAFE = serializers.IntegerField()
    UNWANTED = serializers.IntegerField()
    DANGEROUS = serializers.IntegerField()


class CampaignPcaPointSerializer(serializers.Serializer):
    x = serializers.FloatField()
    y = serializers.FloatField()
    label = serializers.CharField()
    suspicious_case_id = serializers.CharField(allow_null=True, required=False)
    sourceRefs = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
    )


class CampaignPcaResponseSerializer(serializers.Serializer):
    points = CampaignPcaPointSerializer(many=True)
    explained_variance = serializers.ListField(
        child=serializers.FloatField(),
        min_length=2,
        max_length=2,
    )


class CampaignMailVolumeBandSerializer(serializers.Serializer):
    name = serializers.CharField()
    start = serializers.CharField()
    end = serializers.CharField()


class CampaignMailVolumeResponseSerializer(serializers.Serializer):
    dates = serializers.ListField(child=serializers.CharField())
    non_danger = serializers.ListField(child=serializers.IntegerField())
    dangerous = serializers.ListField(child=serializers.IntegerField())
    campaigns = CampaignMailVolumeBandSerializer(many=True)