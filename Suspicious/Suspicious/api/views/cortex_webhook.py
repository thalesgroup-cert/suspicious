"""POST /api/connectors/<name>/webhook/ and its old alias POST /api/cortex/webhook/.

An analysis engine calls this when a job finishes. All behaviour (authentication through the
connector's own webhook, 1 h jobId dedup, ledger lookup, reconcile_case dispatch) lives in
connectors.engines.handle_webhook. The cron poll (update_ongoing_cases) stays the fallback
for missed deliveries.
"""
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from connectors.engines import handle_webhook


def _handle(name: str, request: Request) -> Response:
    code, body = handle_webhook(name, request.headers, request.data)
    return Response(body, status=code)


class ConnectorWebhookView(APIView):
    authentication_classes = []
    permission_classes = []
    throttle_classes = []

    def post(self, request: Request, name: str) -> Response:
        return _handle(name, request)


class CortexWebhookView(ConnectorWebhookView):
    def post(self, request: Request) -> Response:
        return _handle("cortex", request)
