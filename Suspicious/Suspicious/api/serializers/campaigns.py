from rest_framework import serializers


class CampaignPcaQuerySerializer(serializers.Serializer):
    limit = serializers.IntegerField(min_value=1, max_value=5000, default=1500)


class CampaignPeriodQuerySerializer(serializers.Serializer):
    days = serializers.IntegerField(min_value=7, max_value=90, default=15)


class CampaignClassificationCountsSerializer(serializers.Serializer):
    SAFE = serializers.IntegerField(min_value=0)
    UNWANTED = serializers.IntegerField(min_value=0)
    SUSPICIOUS = serializers.IntegerField(min_value=0)
    DANGEROUS = serializers.IntegerField(min_value=0)


class CampaignPcaPointSerializer(serializers.Serializer):
    x = serializers.FloatField()
    y = serializers.FloatField()
    z = serializers.FloatField(required=False, default=0.0)
    label = serializers.CharField()
    suspicious_case_id = serializers.CharField(allow_null=True, required=False)
    mail_subject = serializers.CharField(allow_null=True, required=False, default=None)
    sourceRefs = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
        default=list,
    )
    date = serializers.DateField(format="%Y-%m-%d", allow_null=True, required=False, default=None)


class CampaignPcaResponseSerializer(serializers.Serializer):
    points = CampaignPcaPointSerializer(many=True)
    explained_variance = serializers.ListField(
        child=serializers.FloatField(),
        min_length=2,
        max_length=3,
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


class CampaignSummaryPeriodSerializer(serializers.Serializer):
    start = serializers.DateField(format="%Y-%m-%d")
    end = serializers.DateField(format="%Y-%m-%d")


class CampaignSummaryPeakDaySerializer(serializers.Serializer):
    date = serializers.DateField(format="%Y-%m-%d")
    count = serializers.IntegerField(min_value=0)


class CampaignSummaryCampaignSerializer(serializers.Serializer):
    name = serializers.CharField()
    first_seen = serializers.DateTimeField()
    last_seen = serializers.DateTimeField()
    messages = serializers.IntegerField(min_value=0)
    dangerous = serializers.IntegerField(min_value=0)
    dangerous_share = serializers.FloatField(min_value=0.0, max_value=1.0)
    sample_subject = serializers.CharField(allow_null=True)
    case_ids = serializers.ListField(child=serializers.CharField(), max_length=20, allow_empty=True)
    active = serializers.BooleanField()


class CampaignSummaryLargestSerializer(serializers.Serializer):
    name = serializers.CharField()
    messages = serializers.IntegerField(min_value=0)


class CampaignSummaryResponseSerializer(serializers.Serializer):
    days = serializers.IntegerField()
    period = CampaignSummaryPeriodSerializer()
    messages = serializers.IntegerField(min_value=0)
    previous_messages = serializers.IntegerField(min_value=0)
    dangerous = serializers.IntegerField(min_value=0)
    previous_dangerous = serializers.IntegerField(min_value=0)
    dangerous_share = serializers.FloatField(min_value=0.0, max_value=1.0)
    previous_dangerous_share = serializers.FloatField(min_value=0.0, max_value=1.0)
    peak_day = CampaignSummaryPeakDaySerializer(allow_null=True)
    mix = CampaignClassificationCountsSerializer()
    campaigns = CampaignSummaryCampaignSerializer(many=True)
    active_campaigns = serializers.IntegerField(min_value=0)
    active_window_hours = serializers.IntegerField()
    largest_campaign = CampaignSummaryLargestSerializer(allow_null=True)
