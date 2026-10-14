"""Nightly materialisation of the Overall dashboard summary.

The payload comes from the same live aggregation the summary endpoint uses
(dash_utils.regional.summarise). The endpoint itself no longer reads the
snapshot: a row is up to 24 h old, which made the dashboard disagree with
live data (B2); the endpoint computes live with a 120 s cache instead.
"""
from dashboard.dash_utils.regional import summarise
from dashboard.models import DashboardSnapshot


def materialise_snapshot(month: int, year: int) -> None:
    payload = summarise(month, year, None)
    DashboardSnapshot.objects.update_or_create(
        month=month,
        year=year,
        defaults={"payload": {"month": month, "year": year, "scope": "ALL", **payload}},
    )
