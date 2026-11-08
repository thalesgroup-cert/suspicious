"""AI model card endpoints (Plan F, Task 10). Thin: the services decide, the views map their
refusals to fixed messages (never exception text)."""
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


def _paged(qs, request, prefix, row):
    """{count, results} with its own ?<prefix>_limit and ?<prefix>_offset (limit default 50, at most 100)."""
    page = Page()
    page.limit_query_param, page.offset_query_param = f"{prefix}_limit", f"{prefix}_offset"
    rows = page.paginate_queryset(qs, request)
    return {"count": page.count, "results": [row(r) for r in rows]}


def _refused(detail, **extra):
    return Response({"detail": detail, **extra}, status=status.HTTP_409_CONFLICT)


class Read(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrCISO]


class WriteMixin:
    """POST handler shared by the Admin-only writes: validate, resolve the version, call act()."""

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


class Write(WriteMixin, APIView):
    pass


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
        totals, purity = stats.totals(page), stats.purity_many(page)
        return self.get_paginated_response([
            {**version_summary(v), "stats": totals[v.version_id], "purity": purity[v.version_id],
             "age_warning": stats.age_warning(v)} for v in page])


class ShadowView(Read):
    def get(self, request):
        v = ModelVersion.objects.filter(status=S.SHADOW).first()
        if v is None:
            return Response({"shadow": None})
        snap = promotion.snapshot(v)  # read once, shared by the reviews, the lists and the conditions
        reviews = promotion.latest_reviews(v, snap)
        critical = {r.case_id for r in snap["critical"]}
        delta = snap["delta"]
        in_delta = set(delta["candidate_only"]) | set(delta["active_only"])
        agreement = stats.agreement(v)
        flips = ShadowResult.objects.filter(version=v, origin="live").exclude(flip="none") \
            .exclude(would_be_result="").order_by("-created_at", "-pk")
        effects = ShadowCampaignEffect.objects.filter(version=v).order_by("-created_at", "-pk")

        def flip_row(r):
            reviewable = r.case_id in critical  # only critical flips are reviewed (Ruling F6)
            row = {"case_id": r.case_id, "flip": r.flip, "live_result": r.live_result,
                   "would_be_result": r.would_be_result, "reviewable": reviewable}
            if reviewable:
                row["reviewed"] = ("flip", r.case_id) in reviews
            return row

        def effect_row(e):
            reviewable = e.case_id in in_delta
            row = {"case_id": e.case_id, "effect": e.effect, "live_campaign_id": e.live_campaign_id,
                   "reviewable": reviewable}
            if reviewable:
                row["reviewed"] = ("campaign", e.case_id) in reviews
            return row

        return Response({
            **version_summary(v),
            "live_results": agreement["verdict"]["total"],
            "agreement": agreement,
            "flips": _paged(flips, request, "flips", flip_row),
            "campaign_effects": _paged(effects, request, "effects", effect_row),
            "alert_delta": {k: _paged(delta[k], request, k, lambda c: c) for k in ("candidate_only", "active_only")},
            "conditions": promotion.can_promote(v, snap),
        })


class ReviewsView(WriteMixin, ListAPIView):
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

    def act(self, request, version, data):
        promotion.review(version, data["kind"], data["case_id"], request.user, data["note"])
        return Response({"version_id": version.version_id, "kind": data["kind"], "case_id": data["case_id"]},
                        status=status.HTTP_201_CREATED)


def _done(version):
    return Response(version_summary(version))


class ShadowStartView(Write):
    needs_version = True

    def act(self, request, version, data):
        return _done(promotion.start_shadow(version, request.user, data["note"]))


class PromoteView(Write):
    def act(self, request, version, data):
        return _done(promotion.promote(version, request.user, data["note"]))


class RollbackView(Write):
    needs_target = False

    def act(self, request, version, data):
        return _done(promotion.rollback(request.user, data["note"]))


class DiscardView(Write):
    def act(self, request, version, data):
        return _done(promotion.discard(version, request.user, data["note"]))


class ExtendView(Write):
    serializer_class = ExtendSerializer

    def act(self, request, version, data):
        return _done(promotion.extend(version, data["days"], request.user, data["note"]))


class RecheckView(Write):
    def act(self, request, version, data):
        job = retrain.start_recheck(version, request.user)
        return Response({"job_id": job.job_id}, status=status.HTTP_202_ACCEPTED)
