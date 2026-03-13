from django.db.models import Sum
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiParameter

from case_handler.models import Case
from dashboard.models import (
    UserCasesMonthlyStats,
    GroupMonthlyStats,
)
from profiles.models import UserProfile, CISOProfile

from api.serializers.home import (
    HomeSummaryResponseSerializer,
)
from django.utils import timezone
from django.db.models import Sum
from rest_framework.exceptions import ValidationError

@extend_schema(
    parameters=[
        OpenApiParameter(name="month", type=int, required=False),
        OpenApiParameter(name="year", type=int, required=False),
    ],
    responses=HomeSummaryResponseSerializer,
)
class HomeSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        month = self._parse_int_query_param(
            request, "month", min_value=1, max_value=12, required=False
        )
        year = self._parse_int_query_param(
            request, "year", min_value=1, required=False
        )

        now = timezone.now()
        if month is None:
            month = now.month
        if year is None:
            year = now.year

        month_str = f"{month:02d}"
        year_str = str(year)

        groups = set(request.user.groups.values_list("name", flat=True))
        is_ciso = "CISO" in groups
        is_cert = "CERT" in groups

        user_profile = UserProfile.objects.filter(user=request.user).first()
        ciso_profile = CISOProfile.objects.filter(user=request.user).first()
        profile = ciso_profile if is_ciso and ciso_profile else user_profile

        user_stats = (
            UserCasesMonthlyStats.objects
            .filter(user=request.user, month=month_str, year=year_str)
            .aggregate(
                total_cases=Sum("total_cases"),
                safe=Sum("safe_cases"),
                inconclusive=Sum("inconclusive_cases"),
                suspicious=Sum("suspicious_cases"),
                dangerous=Sum("dangerous_cases"),
            )
        )

        total_cases = int(user_stats["total_cases"] or 0)
        safe = int(user_stats["safe"] or 0)
        inconclusive = int(user_stats["inconclusive"] or 0)
        suspicious = int(user_stats["suspicious"] or 0)
        dangerous = int(user_stats["dangerous"] or 0)

        challenge_cases = Case.objects.filter(
            is_challenged=True,
        ).count()
        
        region = self._clean_profile_value(getattr(profile, "region", None))
        country = self._clean_profile_value(getattr(profile, "country", None))
        gbu = self._clean_profile_value(getattr(profile, "gbu", None))

        ciso_scope = None
        if ciso_profile:
            ciso_scope = self._clean_scope(ciso_profile.scope)

        show_scope_modal = bool(is_ciso and not ciso_scope)

        scope_total_cases = 0
        scope_danger_counts = {
            "safe": 0,
            "inconclusive": 0,
            "suspicious": 0,
            "dangerous": 0,
        }

        if is_ciso and ciso_scope:
            group_stats_qs = GroupMonthlyStats.objects.filter(
                month=month_str,
                year=year_str,
            )

            scope_groups = self._parse_scope_groups(ciso_scope)

            if scope_groups is not None:
                group_stats_qs = group_stats_qs.filter(group_name__in=scope_groups)

            scope_stats = group_stats_qs.aggregate(
                total_cases=Sum("total_cases"),
                safe=Sum("safe_cases"),
                inconclusive=Sum("inconclusive_cases"),
                suspicious=Sum("suspicious_cases"),
                dangerous=Sum("dangerous_cases"),
            )

            scope_total_cases = int(scope_stats["total_cases"] or 0)
            scope_danger_counts = {
                "safe": int(scope_stats["safe"] or 0),
                "inconclusive": int(scope_stats["inconclusive"] or 0),
                "suspicious": int(scope_stats["suspicious"] or 0),
                "dangerous": int(scope_stats["dangerous"] or 0),
            }

        spotlight = self._build_spotlight(
            is_ciso=is_ciso,
            is_cert=is_cert,
            total_cases=scope_total_cases if is_ciso else total_cases,
            challenge_cases=challenge_cases,
        )

        payload = {
            "show_scope_modal": show_scope_modal,
            "monthly": {
                "everyone_items": total_cases,
                "scope_items": scope_total_cases if is_ciso else 0,
                "scope_name": ciso_scope,
            },
            "danger_counts": {
                "safe": safe,
                "inconclusive": inconclusive,
                "suspicious": suspicious,
                "dangerous": dangerous,
            },
            "scope_danger_counts": scope_danger_counts if is_ciso else None,
            "suggested_scopes": {
                "region": region,
                "country": country,
                "gbu": gbu,
            },
            "spotlight": spotlight,
        }

        return Response(payload)

    @staticmethod
    def _clean_profile_value(value):
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    @staticmethod
    def _clean_scope(value):
        if value is None:
            return None
        value = str(value).strip()
        if not value or value.lower() == "not defined":
            return None
        return value

    @staticmethod
    def _parse_scope_groups(scope: str):
        """
        Convert a scope string into a list of group names.
        """
        if not scope:
            return []

        normalized = scope.strip()
        if normalized.upper() == "ALL":
            return None

        parts = [part.strip() for part in normalized.split("|")]
        return [part for part in parts if part]

    @staticmethod
    def _build_spotlight(is_ciso: bool, is_cert: bool, total_cases: int, challenge_cases: int):
        if is_ciso:
            return {
                "title": "CISO overview",
                "description": (
                    f"There are {total_cases} items in your current scope this month. "
                    "Use the dashboard to review broader activity and trends."
                ),
                "cta_label": "Open dashboard",
                "cta_path": "/dashboard",
            }

        if is_cert:
            return {
                "title": "Investigation workspace",
                "description": (
                    f"Everyone has submitted {total_cases} cases this month. "
                    f"    - Number of ongoing challenges : {challenge_cases} "
                    "Open Investigation to review and triage cases."
                ),
                "cta_label": "Open investigation",
                "cta_path": "/investigation",
            }

        return {
            "title": "Your monthly activity",
            "description": (
                f"You have submitted {total_cases} item"
                f"{'' if total_cases == 1 else 's'} this month."
            ),
            "cta_label": "Submit an item",
            "cta_path": "/submit",
        }

    @staticmethod
    def _parse_int_query_param(
        request,
        name: str,
        min_value: int = None,
        max_value: int = None,
        required: bool = True,
    ):
        raw_value = request.query_params.get(name)

        if raw_value in (None, ""):
            if required:
                raise ValidationError({name: "This query parameter is required."})
            return None

        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            raise ValidationError({name: "Must be an integer."})

        if min_value is not None and value < min_value:
            raise ValidationError({name: f"Must be >= {min_value}."})
        if max_value is not None and value > max_value:
            raise ValidationError({name: f"Must be <= {max_value}."})

        return value
