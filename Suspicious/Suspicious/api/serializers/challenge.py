from rest_framework import serializers


class CaseChallengeTokenQuerySerializer(serializers.Serializer):
    token = serializers.CharField(required=True, trim_whitespace=True, allow_blank=False)

    def validate_token(self, value: str) -> str:
        token = value.strip()
        if not token:
            raise serializers.ValidationError("Token is required.")
        return token


class SubmissionChallengeSerializer(serializers.Serializer):
    proposed_result = serializers.ChoiceField(choices=["Safe", "Dangerous"])
    reason = serializers.CharField(
        required=False, allow_blank=True, default="",
        trim_whitespace=True, max_length=2000,
    )