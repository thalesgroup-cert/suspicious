"""Build the serializable CaseEvent snapshot from a Case instance."""
from __future__ import annotations

from django.utils import timezone

from connectors.base import CaseEvent


def build_case_event(event_name: str, case) -> CaseEvent:
    reporter_email = getattr(getattr(case, "reporter", None), "email", "") or ""
    return CaseEvent(
        event=event_name,
        case_id=case.id,
        status=str(getattr(case, "status", "") or ""),
        results=str(getattr(case, "results", "") or ""),
        final_score=getattr(case, "final_score", None),
        confidence=getattr(case, "confidence", None),
        reporter_email=reporter_email,
        created_at=timezone.now().isoformat(),
    )
