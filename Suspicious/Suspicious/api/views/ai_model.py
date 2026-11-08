"""AI model card endpoints (Plan F, Task 10). Thin: the services decide, the views map their
refusals to fixed messages (never exception text)."""
from django.db.models import Sum
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ai_model import promotion, registry, retrain, stats
from ai_model.models import ModelVersion, ShadowCampaignEffect, ShadowResult, ShadowReview
from ai_model.serversync import ReloadRefused
from api.permissions.ai_model import IsAdmin, IsAdminOrCISO
from api.serializers.ai_model import (ActionSerializer, ExtendSerializer, ReviewSerializer,
                                      version_summary)

S = ModelVersion.Status
MAX_LIMIT = 100


class Page(LimitOffsetPagination):
    default_limit = 50
    max_limit = MAX_LIMIT


def _limited(qs, request, row):
    """{count, results} bounded by ?limit= (default 50, at most 100)."""
    try:
        n = max(1, min(int(request.query_params.get("limit", 50)), MAX_LIMIT))
    except ValueError:
        n = 50
    return {"count": qs.count(), "results": [row(r) for r in qs[:n]]}


def _refused(detail, **extra):
    return Response({"detail": detail, **extra}, status=status.HTTP_409_CONFLICT)


class Read(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrCISO]


class Write(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]
    serializer_class = ActionSerializer
    needs_version = False  # True: version_id is required, no default to the shadow
    needs_target = True  # False: act() may take version None

    def post(self, request):
        ser = self.serializer_class(data=request.data)
        ser.is_valid(raise_exception=True)
        data = ser.validated_data
        vid = data.get("version_id")
        if vid:
            version = ModelVersion.objects.filter(version_id=vid).first()
            if version is None:
                return Response({"detail": "Unknown version."}, status=status.HTTP_404_NOT_FOUND)
        elif self.needs_version:
            return Response({"version_id": ["This field is required."]}, status=status.HTTP_400_BAD_REQUEST)
        else:
            version = ModelVersion.objects.filter(status=S.SHADOW).first()
            if version is None and self.needs_target:
                return _refused("There is no shadow version.", codes=["not_shadow"])
        try:
            return self.act(request, version, data)
        except promotion.PromotionRefused as refused:
            return _refused("Promotion refused.", codes=refused.codes)
        except ReloadRefused:
            return _refused("The inference server refused the change; it was reverted.")
        except (registry.RegistryError, retrain.RetrainRefused):
            return _refused("The change was refused in the current state.")


class StatusView(Read):
    def get(self, request):
        pick = lambda s: (lambda v: version_summary(v) if v else None)(ModelVersion.objects.filter(status=s).first())
        job = retrain.running_job()
        return Response({"active": pick(S.ACTIVE), "previous": pick(S.PREVIOUS), "shadow": pick(S.SHADOW),
                         "job_running": job is not None, "job_id": job.job_id if job else None})


class VersionsView(ListAPIView, Read):
    pagination_class = Page

    def get_queryset(self):
        return ModelVersion.objects.order_by("-created_at", "-pk")

    def list(self, request, *args, **kwargs):
        page = self.paginate_queryset(self.get_queryset())
        rows = []
        for v in page:
            total = v.stats.aggregate(scored=Sum("scored"), dangerous=Sum("dangerous"), checks=Sum("campaign_checks"),
                                      created=Sum("created"), joined=Sum("joined"), alerts=Sum("alerts"))
            rows.append({**version_summary(v), "stats": {k: n or 0 for k, n in total.items()},
                         "purity": stats.purity(v), "age_warning": stats.age_warning(v)})
        return self.get_paginated_response(rows)


class ShadowView(Read):
    def get(self, request):
        v = ModelVersion.objects.filter(status=S.SHADOW).first()
        if v is None:
            return Response({"shadow": None})
        live = ShadowResult.objects.filter(version=v, origin="live").exclude(would_be_result="")
        reviews = promotion.latest_reviews(v)
        cls = [(r.result, r.case.ai_assessment.result) for r in live.select_related("case__ai_assessment")
               if hasattr(r.case, "ai_assessment")]
        verdict = list(live.values_list("live_result", "would_be_result"))
        agree = lambda pairs: {"agree": sum(a.lower() == b.lower() for a, b in pairs), "total": len(pairs)}
        flips = ShadowResult.objects.filter(version=v, origin="live").exclude(flip="none").exclude(would_be_result="") \
            .order_by("-created_at", "-pk")
        effects = ShadowCampaignEffect.objects.filter(version=v).order_by("-created_at", "-pk")
        delta = promotion.alert_delta(v)
        return Response({
            **version_summary(v),
            "live_results": live.count(),
            "agreement": {"class": agree(cls), "verdict": agree(verdict)},
            "flips": _limited(flips, request, lambda r: {
                "case_id": r.case_id, "flip": r.flip, "live_result": r.live_result,
                "would_be_result": r.would_be_result, "reviewed": ("flip", r.case_id) in reviews}),
            "campaign_effects": _limited(effects, request, lambda e: {
                "case_id": e.case_id, "effect": e.effect, "live_campaign_id": e.live_campaign_id,
                "reviewed": ("campaign", e.case_id) in reviews}),
            "alert_delta": delta,
            "conditions": promotion.can_promote(v),
        })


class ReviewsView(ListAPIView):
    pagination_class = Page

    def get_permissions(self):
        cls = IsAdmin if self.request.method == "POST" else IsAdminOrCISO
        return [IsAuthenticated(), cls()]

    def get_queryset(self):
        qs = ShadowReview.objects.select_related("user", "version").order_by("-at", "-pk")
        vid = self.request.query_params.get("version_id")
        return qs.filter(version__version_id=vid) if vid else qs

    def list(self, request, *args, **kwargs):
        rows = [{"version_id": r.version.version_id, "kind": r.kind, "case_id": r.case_id,
                 "user": r.user.get_username() if r.user else None, "note": r.note, "at": r.at}
                for r in self.paginate_queryset(self.get_queryset())]
        return self.get_paginated_response(rows)

    serializer_class = ReviewSerializer
    needs_version = False
    needs_target = True
    post = Write.post

    def act(self, request, version, data):
        promotion.review(version, data["kind"], data["case_id"], request.user, data["note"])
        return Response({"version_id": version.version_id, "kind": data["kind"], "case_id": data["case_id"]},
                        status=status.HTTP_201_CREATED)


def _done(version):
    return Response(version_summary(version))


class ShadowStartView(Write):
    needs_version = True

    def act(self, request, version, data):
        return _done(registry.set_shadow(version, request.user, data["note"]))


class PromoteView(Write):
    def act(self, request, version, data):
        return _done(promotion.promote(version, request.user, data["note"]))


class RollbackView(Write):
    needs_target = False

    def act(self, request, version, data):
        return _done(promotion.rollback(request.user, data["note"]))


class DiscardView(Write):
    def act(self, request, version, data):
        return _done(registry.discard(version, request.user, data["note"]))


class ExtendView(Write):
    serializer_class = ExtendSerializer

    def act(self, request, version, data):
        return _done(promotion.extend(version, data["days"], request.user, data["note"]))


class RecheckView(Write):
    def act(self, request, version, data):
        job = retrain.start_recheck(version, request.user)
        return Response({"job_id": job.job_id}, status=status.HTTP_202_ACCEPTED)
