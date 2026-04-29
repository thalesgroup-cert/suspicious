from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.serializers.campaigns import (
    CampaignClassificationCountsSerializer,
    CampaignMailVolumeResponseSerializer,
    CampaignPcaQuerySerializer,
    CampaignPcaResponseSerializer,
)
from api.services.campaigns import CampaignQueryService
from api.services.campaigns.service import DEFAULT_PCA_LIMIT, MAX_PCA_LIMIT


def _validated_response(serializer_cls, payload):
    serializer = serializer_cls(data=payload)
    serializer.is_valid(raise_exception=True)
    return Response(serializer.data)


@extend_schema(
    tags=["Campaigns"],
)
class CampaignClassificationCountsView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="campaign_classification_counts",
        summary="Get campaign classification counts",
        description=(
            "Return aggregate message counts by top-level classification for the current "
            "Chroma collection.\n\n"
            "**Label semantics**\n"
            "- `SAFE`: benign content.\n"
            "- `UNWANTED`: unwanted but not dangerous content.\n"
            "- `DANGEROUS`: confirmed dangerous content.\n\n"
            "**Aggregation rule**\n"
            "- Records labeled `SUSPICIOUS` are folded into `UNWANTED` for this endpoint.\n"
            "- This is intentional to preserve the existing frontend contract, which expects "
            "three buckets only: `SAFE`, `UNWANTED`, and `DANGEROUS`.\n\n"
            "**Implementation note**\n"
            "- Counts are computed by scanning metadata and normalizing the `classification` "
            "field rather than issuing multiple per-label queries."
        ),
        responses={
            200: OpenApiResponse(
                response=CampaignClassificationCountsSerializer,
                description=(
                    "Three-bucket classification counts. `SUSPICIOUS` is aggregated into "
                    "`UNWANTED`."
                ),
            ),
        },
        examples=[
            OpenApiExample(
                "Classification counts",
                value={
                    "SAFE": 128,
                    "UNWANTED": 41,
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
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="campaign_pca",
        summary="Get a 2D PCA projection of sampled embeddings",
        description=(
            "Return a two-dimensional PCA projection of a deterministic sample of embeddings "
            "from the current Chroma collection.\n\n"
            "**Label semantics**\n"
            "- Point `label` is the normalized uppercase value of the metadata "
            "`classification` field.\n"
            "- Unlike the counts endpoint, this endpoint does **not** fold `SUSPICIOUS` into "
            "`UNWANTED`; labels are exposed as stored after normalization.\n\n"
            "**Sampling behavior**\n"
            "- The endpoint does **not** fetch all embeddings first.\n"
            "- It first walks collection IDs, then selects a deterministic subset up to `limit` "
            "using a stable hash of the Chroma record ID.\n"
            "- The same collection contents and `limit` produce the same sample order.\n"
            "- After sampling, embeddings are grouped by vector dimensionality and PCA is run "
            "only on the largest dimension bucket to avoid mixing incompatible embeddings.\n\n"
            "**Numerical behavior**\n"
            "- PCA is computed with centered vectors and SVD in float64.\n"
            "- `explained_variance` contains the variance ratios for PC1 and PC2.\n"
            "- If only one usable dimension exists, PC2 is returned as zero."
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
                description="PCA projection points and explained variance ratios for PC1 and PC2.",
            ),
        },
        examples=[
            OpenApiExample(
                "PCA response",
                value={
                    "explained_variance": [0.37, 0.18],
                    "points": [
                        {
                            "x": -2.14,
                            "y": 0.88,
                            "label": "SAFE",
                            "suspicious_case_id": "1234",
                            "sourceRefs": ["sender-domain-a", "subject-cluster-1"],
                        },
                        {
                            "x": 1.27,
                            "y": -0.42,
                            "label": "SUSPICIOUS",
                            "suspicious_case_id": "1250",
                            "sourceRefs": ["sender-domain-b"],
                        },
                    ],
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request):
        params = CampaignPcaQuerySerializer(data=request.query_params)
        params.is_valid(raise_exception=True)
        limit = int(params.validated_data.get("limit", DEFAULT_PCA_LIMIT))

        payload = CampaignQueryService().get_pca(limit)
        return _validated_response(CampaignPcaResponseSerializer, payload)


@extend_schema(
    tags=["Campaigns"],
)
class CampaignMailVolumeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        operation_id="campaign_mail_volume",
        summary="Get mail volume for the last 15 days with inferred campaign windows",
        description=(
            "Return daily mail volume for the last 15 UTC days and inferred campaign date bands.\n\n"
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
            "`sourceRefs` may merge unrelated messages into the same displayed band."
        ),
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
        payload = CampaignQueryService().get_mail_volume()
        return _validated_response(CampaignMailVolumeResponseSerializer, payload)
