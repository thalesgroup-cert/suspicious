from rest_framework import serializers


class CampaignPcaQuerySerializer(serializers.Serializer):
    limit = serializers.IntegerField(min_value=1, max_value=5000, default=1500)


class CampaignClassificationCountsSerializer(serializers.Serializer):
    SAFE = serializers.IntegerField(min_value=0)
    UNWANTED = serializers.IntegerField(min_value=0)
    DANGEROUS = serializers.IntegerField(min_value=0)


class CampaignPcaPointSerializer(serializers.Serializer):
    x = serializers.FloatField()
    y = serializers.FloatField()
    label = serializers.CharField()
    suspicious_case_id = serializers.CharField(allow_null=True, required=False)
    mail_subject = serializers.CharField(allow_null=True, required=False, default=None)
    sourceRefs = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
        default=list,
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
    start = serializers.DateTimeField()
    end = serializers.DateTimeField()


class CampaignMailVolumeResponseSerializer(serializers.Serializer):
    dates = serializers.ListField(child=serializers.DateField(format="%Y-%m-%d"))
    non_danger = serializers.ListField(child=serializers.IntegerField(min_value=0))
    dangerous = serializers.ListField(child=serializers.IntegerField(min_value=0))
    campaigns = CampaignMailVolumeBandSerializer(many=True)