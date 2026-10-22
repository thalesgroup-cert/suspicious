from rest_framework import serializers


class CaseChallengeTokenQuerySerializer(serializers.Serializer):
    token = serializers.CharField(required=True, trim_whitespace=True, allow_blank=False)

    def validate_token(self, value: str) -> str:
        token = value.strip()
        if not token:
            raise serializers.ValidationError("Token is required.")
        return token


MIN_REASON_LENGTH = 10


class SubmissionChallengeSerializer(serializers.Serializer):
    proposed_result = serializers.ChoiceField(choices=["Safe", "Dangerous"])
    reason = serializers.CharField(
        trim_whitespace=True, min_length=MIN_REASON_LENGTH, max_length=2000,
        error_messages={
            "required": "Say why the verdict is wrong.",
            "blank": "Say why the verdict is wrong.",
            "min_length": f"Give at least {MIN_REASON_LENGTH} characters of reason.",
        },
    )