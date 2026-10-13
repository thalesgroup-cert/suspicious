from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
)
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions.dashboard import StatsReadPermission
from api.serializers.campaigns import (
    CampaignClassificationCountsSerializer,
    CampaignMailVolumeResponseSerializer,
    CampaignNeighboursResponseSerializer,
    CampaignPcaQuerySerializer,
    CampaignPcaResponseSerializer,
    CampaignPeriodQuerySerializer,
    CampaignSummaryResponseSerializer,
)
from api.services.campaigns import CampaignQueryService
from api.services.campaigns.service import (
    DEFAULT_PCA_LIMIT,
    DEFAULT_PERIOD_DAYS,
    MAIL_VOLUME_CACHE_TTL_SECONDS,
    MAX_PCA_LIMIT,
    MAX_PERIOD_DAYS,
    MIN_PERIOD_DAYS,
)
from api.services.campaigns import neighbours as nb
from api.services.campaigns.summary import (
    ACTIVE_WINDOW_HOURS,
    CACHE_TTL_SECONDS,
    get_campaign_summary,
)


DAYS_PARAMETER = OpenApiParameter(
    name="days",
    type=int,
    location=OpenApiParameter.QUERY,
    required=False,
    description=(
        "Period length in UTC days, today included. "
        f"Default: {DEFAULT_PERIOD_DAYS}. Range: {MIN_PERIOD_DAYS}-{MAX_PERIOD_DAYS}; "
        "values outside the range return 400."
    ),
)


LIMIT_PARAMETER = OpenApiParameter(
    name="limit",
    type=int,
    location=OpenApiParameter.QUERY,
    required=False,
    description=(
        "Maximum number of records to sample. "
        f"Default: {DEFAULT_PCA_LIMIT}. Range: 1-{MAX_PCA_LIMIT}; values outside return 400."
    ),
)


def _pca_limit(request) -> int:
    params = CampaignPcaQuerySerializer(data=request.query_params)
    params.is_valid(raise_exception=True)
    return int(params.validated_data.get("limit", DEFAULT_PCA_LIMIT))


def _period_days(request) -> int:
    params = CampaignPeriodQuerySerializer(data=request.query_params)
    params.is_valid(raise_exception=True)
    return int(params.validated_data["days"])


def _validated_response(serializer_cls, payload):
    serializer = serializer_cls(data=payload)
    serializer.is_valid(raise_exception=True)
    return Response(serializer.data)


@extend_schema(
    tags=["Campaigns"],
)
class CampaignClassificationCountsView(APIView):
    permission_classes = [StatsReadPermission]

    @extend_schema(
        operation_id="campaign_classification_counts",
        summary="Get campaign classification counts",
        description=(
            "Return aggregate message counts by top-level classification for the current "
            "Chroma collection.\n\n"
            "**Label semantics**\n"
            "- `SAFE`: benign content.\n"
            "- `UNWANTED`: unwanted but not dangerous content.\n"
            "- `SUSPICIOUS`: suspicious content.\n"
            "- `DANGEROUS`: confirmed dangerous content.\n\n"
            "**Aggregation rule**\n"
            "- The four labels are counted as stored (no folding). Records with any other "
            "or no `classification` are not counted.\n\n"
            "**Implementation note**\n"
            "- Counts are computed by scanning metadata and normalizing the `classification` "
            "field rather than issuing multiple per-label queries."
        ),
        responses={
            200: OpenApiResponse(
                response=CampaignClassificationCountsSerializer,
                description="Four-bucket classification counts, as stored.",
            ),
        },
        examples=[
            OpenApiExample(
                "Classification counts",
                value={
                    "SAFE": 128,
                    "UNWANTED": 30,
                    "SUSPICIOUS": 11,
                    "DANGEROUS": 9,
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request):
        payload = CampaignQueryService().get_classification_counts()
        return _validated_response(CampaignClassificationCountsSerializer, payload)


@extend_schema(
    tags=["Campaigns"],
)
class CampaignPcaView(APIView):
    permission_classes = [StatsReadPermission]

    @extend_schema(
        operation_id="campaign_pca",
        summary="Get a 3D PCA projection of sampled embeddings",
        description=(
            "Return a three-dimensional PCA projection of a deterministic sample of embeddings "
            "from the current Chroma collection.\n\n"
            "**Label semantics**\n"
            "- Point `label` is the normalized uppercase value of the metadata "
            "`classification` field.\n"
            "- Labels are exposed as stored after normalization, like the counts endpoint.\n\n"
            "**Sampling behavior**\n"
            "- The endpoint does **not** fetch all embeddings first.\n"
            "- It first walks collection IDs, then selects a deterministic subset up to `limit` "
            "using a stable hash of the Chroma record ID.\n"
            "- The same collection contents and `limit` produce the same sample order.\n"
            "- After sampling, embeddings are grouped by vector dimensionality and PCA is run "
            "only on the largest dimension bucket to avoid mixing incompatible embeddings.\n\n"
            "**Numerical behavior**\n"
            "- PCA is computed with centered vectors and SVD in float64.\n"
            "- `explained_variance` contains the variance ratios for PC1, PC2 and PC3 "
            "(always 3 values from this server; clients should also accept 2).\n"
            "- Each component's sign is normalised (largest-magnitude loading positive) so "
            "the projection does not mirror between refreshes.\n"
            "- Missing components (one vector, 1-dimensional vectors, two vectors, zero "
            "variance) are returned as zero coordinates and zero ratios, never NaN.\n\n"
            "**Point date**\n"
            "- `date` is the UTC sent date (`YYYY-MM-DD`) extracted like the mail-volume "
            "endpoint does, or `null` when the record carries no usable date."
        ),
        parameters=[
            OpenApiParameter(
                name="limit",
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    "Maximum number of records to sample before PCA. "
                    f"Default: {DEFAULT_PCA_LIMIT}. Maximum: {MAX_PCA_LIMIT}."
                ),
            ),
        ],
        responses={
            200: OpenApiResponse(
                response=CampaignPcaResponseSerializer,
                description="PCA projection points and explained variance ratios for PC1-PC3.",
            ),
        },
        examples=[
            OpenApiExample(
                "PCA response",
                value={
                    "explained_variance": [0.37, 0.18, 0.09],
                    "points": [
                        {
                            "x": -2.14,
                            "y": 0.88,
                            "z": 0.31,
                            "label": "SAFE",
                            "suspicious_case_id": "1234",
                            "sourceRefs": ["sender-domain-a", "subject-cluster-1"],
                            "date": "2026-03-02",
                        },
                        {
                            "x": 1.27,
                            "y": -0.42,
                            "z": -0.05,
                            "label": "SUSPICIOUS",
                            "suspicious_case_id": "1250",
                            "sourceRefs": ["sender-domain-b"],
                            "date": None,
                        },
                    ],
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request):
        payload = CampaignQueryService().get_pca(_pca_limit(request))
        return _validated_response(CampaignPcaResponseSerializer, payload)


@extend_schema(
    tags=["Campaigns"],
)
class CampaignMailVolumeView(APIView):
    permission_classes = [StatsReadPermission]

    @extend_schema(
        operation_id="campaign_mail_volume",
        summary="Get mail volume for the last `days` days with inferred campaign windows",
        description=(
            "Return daily mail volume for the last `days` UTC days (today included) and "
            "inferred campaign date bands clamped to that window.\n\n"
            "**Label semantics**\n"
            "- `dangerous` counts only records whose normalized `classification` is `DANGEROUS`.\n"
            "- `non_danger` counts every other classified or unclassified record that has a usable date.\n\n"
            "**Date extraction behavior**\n"
            "- The endpoint prefers parsed mail headers such as `Date` when available.\n"
            "- It then falls back to known metadata timestamp fields such as `sent_date`, `date`, "
            "`received_at`, `created_at`, `timestamp`, and related keys.\n"
            "- All date bucketing is performed in UTC.\n\n"
            "**Campaign grouping heuristic**\n"
            "- Campaign bands are inferred by grouping records that share the same normalized "
            "`sourceRefs` set.\n"
            "- `sourceRefs` are parsed defensively from arrays or string-encoded lists, de-duplicated, "
            "sorted, and then used as the grouping key.\n"
            "- This is a heuristic, not a guaranteed campaign identifier. Reused or noisy "
            "`sourceRefs` may merge unrelated messages into the same displayed band.\n"
            "- Band start/end use every dated record of the group, future-dated ones "
            "included, then are clamped to the window (the summary endpoint skips "
            "future-dated records).\n\n"
            f"Responses are cached for {MAIL_VOLUME_CACHE_TTL_SECONDS} seconds per `days` value."
        ),
        parameters=[DAYS_PARAMETER],
        responses={
            200: OpenApiResponse(
                response=CampaignMailVolumeResponseSerializer,
                description=(
                    "Daily UTC mail volume and campaign date bands inferred from shared `sourceRefs`."
                ),
            ),
        },
        examples=[
            OpenApiExample(
                "Mail volume response",
                value={
                    "dates": [
                        "2026-03-02",
                        "2026-03-03",
                        "2026-03-04",
                    ],
                    "non_danger": [4, 7, 3],
                    "dangerous": [1, 0, 2],
                    "campaigns": [
                        {
                            "name": "sender-domain-a, subject-cluster-1",
                            "start": "2026-03-02T00:00:00Z",
                            "end": "2026-03-04T23:59:59.999999Z",
                        }
                    ],
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request):
        payload = CampaignQueryService().get_mail_volume(_period_days(request))
        return _validated_response(CampaignMailVolumeResponseSerializer, payload)


@extend_schema(
    tags=["Campaigns"],
)
class CampaignSummaryView(APIView):
    permission_classes = [StatsReadPermission]

    @extend_schema(
        operation_id="campaign_summary",
        summary="Get period KPIs and campaigns from the message store",
        description=(
            "Return indicators for the last `days` UTC days (today included) and the "
            "preceding period of the same length, computed in one scan of the message "
            "store metadata. Organisation-wide; records without a usable date and "
            "future-dated records are skipped.\n\n"
            "**Fields**\n"
            "- `messages` / `previous_messages`, `dangerous` / `previous_dangerous`, and "
            "`dangerous_share` / `previous_dangerous_share` (dangerous / messages, `null` "
            "when that period has no messages).\n"
            "- `peak_day`: the day with most messages in the period (earliest on ties), "
            "`null` when empty.\n"
            "- `mix`: four-bucket classification counts for the period, as stored.\n"
            "- `unclassified`: messages in the period whose label is none of the four "
            "(e.g. `NONE`, `UNKNOWN`, empty); `messages = sum(mix) + unclassified`.\n"
            "- `campaigns`: one entry per group of messages in the period, sorted by "
            "message count. `first_seen` / `last_seen` are the first and last message of "
            "the group seen within the period. `case_ids` lists the 20 most recent case "
            "ids, newest first; `sample_subject` is the subject of the earliest message "
            "in the period that has one.\n"
            f"- `active`: `last_seen` within `active_window_hours` ({ACTIVE_WINDOW_HOURS}) "
            "of now; `active_campaigns` counts them; `largest_campaign` is the first entry.\n\n"
            "**Campaign grouping heuristic**\n"
            "- A campaign is the set of messages whose normalized `sourceRefs` are identical. "
            "Messages without `sourceRefs` belong to no campaign. This is a heuristic, not a "
            "guaranteed campaign identifier.\n\n"
            f"Responses are cached for {CACHE_TTL_SECONDS} seconds per `days` value."
        ),
        parameters=[DAYS_PARAMETER],
        responses={
            200: OpenApiResponse(
                response=CampaignSummaryResponseSerializer,
                description="Period KPIs, classification mix and campaigns.",
            ),
        },
        examples=[
            OpenApiExample(
                "Campaign summary",
                value={
                    "days": 15,
                    "period": {"start": "2026-09-29", "end": "2026-10-13"},
                    "messages": 42,
                    "previous_messages": 30,
                    "dangerous": 6,
                    "previous_dangerous": 3,
                    "dangerous_share": 0.142857,
                    "previous_dangerous_share": 0.1,
                    "peak_day": {"date": "2026-10-08", "count": 9},
                    "mix": {"SAFE": 18, "UNWANTED": 10, "SUSPICIOUS": 6, "DANGEROUS": 6},
                    "unclassified": 2,
                    "campaigns": [
                        {
                            "name": "sender-domain-a, subject-cluster-1",
                            "first_seen": "2026-10-07T08:12:00Z",
                            "last_seen": "2026-10-12T16:40:00Z",
                            "messages": 7,
                            "dangerous": 4,
                            "dangerous_share": 0.571429,
                            "sample_subject": "Invoice overdue",
                            "case_ids": ["1207", "1201"],
                            "active": True,
                        }
                    ],
                    "active_campaigns": 1,
                    "active_window_hours": ACTIVE_WINDOW_HOURS,
                    "largest_campaign": {
                        "name": "sender-domain-a, subject-cluster-1",
                        "messages": 7,
                    },
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request):
        payload = get_campaign_summary(_period_days(request))
        return _validated_response(CampaignSummaryResponseSerializer, payload)


@extend_schema(
    tags=["Campaigns"],
)
class CampaignNeighboursView(APIView):
    permission_classes = [StatsReadPermission]

    @extend_schema(
        operation_id="campaign_neighbours",
        summary="Get near-known-bad and novel messages (embedding-space heuristics)",
        description=(
            "Return two short lists computed on the same deterministic sample as the PCA "
            "endpoint (same `limit`, dominant embedding dimension). Both are heuristics: "
            "closeness in embedding space is a hint, not proof of the same campaign.\n\n"
            "**near_known_bad**\n"
            "- Messages not labelled `DANGEROUS` whose `k` nearest neighbours (cosine "
            "similarity, self excluded) are at least `bad_share_threshold` Dangerous.\n"
            "- `score` is that Dangerous share; `nearest_dangerous_case_id` is the case of "
            "the most similar Dangerous neighbour (`null` when it has no case id).\n\n"
            "**novel**\n"
            "- Messages dated within the last `novel_window_days` UTC days (today included) "
            "whose nearest-neighbour cosine distance (1 - similarity) exceeds the "
            "`novelty_percentile` percentile of the sample's nearest-neighbour distances: "
            "possible new campaigns. `score` is that distance; "
            "`nearest_dangerous_case_id` is always `null`.\n\n"
            "**Behaviour**\n"
            "- Each list is sorted by `score` descending (then date, newest first, then case "
            f"id) and capped at {nb.MAX_ITEMS}.\n"
            "- Zero vectors are ignored; fewer than `k + 1` usable vectors yields empty lists.\n"
            f"- Similarity is computed in chunks of at most {nb.CHUNK_ROWS} rows, never as a "
            "full n x n matrix.\n\n"
            f"Responses are cached for {nb.CACHE_TTL_SECONDS} seconds per `limit` value "
            "(not when the message store is unavailable or the computation fails)."
        ),
        parameters=[LIMIT_PARAMETER],
        responses={
            200: OpenApiResponse(
                response=CampaignNeighboursResponseSerializer,
                description="Heuristic near-known-bad and novel message lists.",
            ),
        },
        examples=[
            OpenApiExample(
                "Neighbours response",
                value={
                    "k": 10,
                    "bad_share_threshold": 0.6,
                    "novelty_percentile": 95,
                    "novel_window_days": 7,
                    "near_known_bad": [
                        {
                            "suspicious_case_id": "1290",
                            "mail_subject": "Your parcel is on hold",
                            "label": "SAFE",
                            "date": "2026-10-12",
                            "score": 0.8,
                            "nearest_dangerous_case_id": "1207",
                        }
                    ],
                    "novel": [
                        {
                            "suspicious_case_id": "1301",
                            "mail_subject": "Payroll portal migration",
                            "label": "SUSPICIOUS",
                            "date": "2026-10-13",
                            "score": 0.41,
                            "nearest_dangerous_case_id": None,
                        }
                    ],
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request):
        payload = nb.get_campaign_neighbours(_pca_limit(request))
        return _validated_response(CampaignNeighboursResponseSerializer, payload)
