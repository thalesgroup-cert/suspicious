from django.db.models import Sum
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.serializers.home import (
    HomeSummaryQuerySerializer,
    HomeSummaryResponseSerializer,
)
from case_handler.models import Case
from dashboard.models import GroupMonthlyStats, UserCasesMonthlyStats, TotalCasesStats
from profiles.models import CISOProfile, UserProfile


@extend_schema(
    parameters=[HomeSummaryQuerySerializer],
    responses={200: HomeSummaryResponseSerializer},
)
class HomeSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    AGGREGATE_MAP = {
        "total_cases": "total_cases",
        "safe": "safe_cases",
        "inconclusive": "inconclusive_cases",
        "suspicious": "suspicious_cases",
        "dangerous": "dangerous_cases",
    }

    def get(self, request):
        params = HomeSummaryQuerySerializer(data=request.query_params)
        params.is_valid(raise_exception=True)

        now = timezone.now()
        month = params.validated_data.get("month", now.month)
        year = params.validated_data.get("year", now.year)

        month_str = f"{month:02d}"
        year_str = str(year)

        group_names = set(request.user.groups.values_list("name", flat=True))
        is_ciso = "CISO" in group_names
        is_cert = "CERT" in group_names

        user_profile = UserProfile.objects.filter(user=request.user).first()
        ciso_profile = CISOProfile.objects.filter(user=request.user).first()
        active_profile = ciso_profile if is_ciso and ciso_profile else user_profile

        ciso_scope = self._clean_scope(getattr(ciso_profile, "scope", None)) if ciso_profile else None
        show_scope_modal = bool(is_ciso and not ciso_scope)

        personal_stats = self._aggregate_user_stats(
            user=request.user,
            month=month_str,
            year=year_str,
        )
        global_stats = self._aggregate_global_stats(
            month=month_str,
            year=year_str,
        )

        scope_stats = None
        if is_ciso and ciso_scope:
            scope_stats = self._aggregate_scope_stats(
                scope=ciso_scope,
                month=month_str,
                year=year_str,
            )

        region = self._clean_profile_value(getattr(active_profile, "region", None))
        country = self._clean_profile_value(getattr(active_profile, "country", None))
        gbu = self._clean_profile_value(getattr(active_profile, "gbu", None))

        if is_ciso and scope_stats is not None:
            primary_danger_counts = self._extract_danger_counts(personal_stats)
            spotlight_total_cases = int(scope_stats["total_cases"])
        else:
            primary_danger_counts = self._extract_danger_counts(personal_stats)
            spotlight_total_cases = int(global_stats["total_cases"])
        

        challenge_cases = 0
        if is_cert:
            challenge_cases = Case.objects.filter(is_challenged=True).count()

        payload = {
            "show_scope_modal": show_scope_modal,
            "monthly": {
                "everyone_items": int(global_stats["total_cases"]),
                "scope_items": int(scope_stats["total_cases"]) if scope_stats is not None else 0,
                "scope_name": ciso_scope if is_ciso else None,
            },
            "danger_counts": primary_danger_counts,
            "scope_danger_counts": (
                self._extract_danger_counts(scope_stats) if scope_stats is not None else None
            ),
            "suggested_scopes": {
                "region": region,
                "country": country,
                "gbu": gbu,
            },
            "spotlight": self._build_spotlight(
                is_ciso=is_ciso,
                is_cert=is_cert,
                total_cases=spotlight_total_cases,
                challenge_cases=challenge_cases,
            ),
        }

        return Response(payload)

    @classmethod
    def _aggregate_user_stats(cls, *, user, month: str, year: str) -> dict:
        return cls._normalize_stats(
            UserCasesMonthlyStats.objects.filter(
                user=user,
                month=month,
                year=year,
            ).aggregate(**cls._build_aggregate_kwargs())
        )

    @classmethod
    def _aggregate_global_stats(cls, *, month: str, year: str) -> dict:
        return cls._normalize_stats(
            TotalCasesStats.objects.filter(
                creation_date__year=year,
                creation_date__month=month,
            ).aggregate(total_cases=Sum("total_cases"))
        )

    @classmethod
    def _aggregate_scope_stats(cls, *, scope: str, month: str, year: str) -> dict:
        qs = GroupMonthlyStats.objects.filter(month=month, year=year)

        scope_groups = cls._parse_scope_groups(scope)
        if scope_groups is not None:
            qs = qs.filter(group_name__in=scope_groups)

        return cls._normalize_stats(qs.aggregate(**cls._build_aggregate_kwargs()))

    @classmethod
    def _build_aggregate_kwargs(cls) -> dict:
        return {
            public_name: Sum(model_field)
            for public_name, model_field in cls.AGGREGATE_MAP.items()
        }

    @staticmethod
    def _normalize_stats(raw_stats: dict) -> dict:
        return {
            "total_cases": int(raw_stats.get("total_cases") or 0),
            "safe": int(raw_stats.get("safe") or 0),
            "inconclusive": int(raw_stats.get("inconclusive") or 0),
            "suspicious": int(raw_stats.get("suspicious") or 0),
            "dangerous": int(raw_stats.get("dangerous") or 0),
        }

    @staticmethod
    def _extract_danger_counts(stats: dict) -> dict:
        return {
            "safe": int(stats["safe"]),
            "inconclusive": int(stats["inconclusive"]),
            "suspicious": int(stats["suspicious"]),
            "dangerous": int(stats["dangerous"]),
        }

    @staticmethod
    def _clean_profile_value(value):
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    @staticmethod
    def _clean_scope(value):
        if value is None:
            return None
        normalized = str(value).strip()
        if not normalized or normalized.lower() == "not defined":
            return None
        return normalized

    @staticmethod
    def _parse_scope_groups(scope: str):
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
                    f"There have been {total_cases} submitted cases this month. "
                    f"Number of ongoing challenges: {challenge_cases}. "
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