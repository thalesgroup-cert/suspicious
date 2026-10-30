"""Replay a campaign the Cortex AI path built through the ai_model connector's detection and
compare the members.

Read-only: it runs in a transaction that is always rolled back, against a scratch Chroma
collection dropped at the end, and emits no event. Safe to run against production data."""
import dataclasses
import secrets

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from ai_model.campaign_profile import current_profile
from ai_model.models import AiAssessment
from case_handler.models import Campaign, CampaignMember, Case
from common.clients import get_chroma_client
from connectors.contrib.ai_model.campaigns import detect_campaign, open_collection
from connectors.contrib.thehive.utils import parse_and_decode_defaultdict
from cortex_job.models import AnalyzerReport


def _cortex_material(case: Case):
    """(assessment, text, headers) from the case's newest successful Cortex AI report, else None.
    The assessment is never saved."""
    report = (
        AnalyzerReport.objects.filter(
            analyzer__name__startswith="AI_Mail", case_jobs__case_id=case.id, status="Success",
        ).order_by("-id").first()
    )
    full = report.report_full if report else None
    if not isinstance(full, dict) or not isinstance(full.get("report"), dict):
        return None
    body = full["report"]
    try:
        headers = parse_and_decode_defaultdict(str(body.get("analyzed_mail_headers", "")))
    except Exception:  # noqa: BLE001 -- keep the raw value, as the Cortex path did
        headers = body.get("analyzed_mail_headers", "")
    assessment = AiAssessment(
        case=case,
        result=str(full.get("classification", "")),
        sub_class=str(full.get("sub_classification") or ""),
        score=float(full.get("malscore") or 0),
        confidence=float(full.get("confidence") or 0) * 100,
        campaign_embedding=str(body.get("email_embedding") or ""),
    )
    return assessment, str(body.get("analyzed_mail_content") or ""), headers


class Command(BaseCommand):
    help = (
        "Replay a stored campaign's members, in case id order, from their Cortex AI reports "
        "through the ai_model connector's campaign detection, and print MATCH when the same "
        "members and trigger come out. A campaign has no trigger field: the stored trigger is "
        "taken to be its highest case id. Changes nothing: rolled-back transaction, scratch "
        "Chroma collection, no event."
    )

    def add_arguments(self, parser):
        parser.add_argument("campaign_ref", help="Campaign.ref of the campaign to replay")

    def handle(self, *args, **opts):
        ref = opts["campaign_ref"]
        campaign = Campaign.objects.filter(ref=ref).first()
        if campaign is None:
            raise CommandError(f"unknown campaign {ref!r}")
        stored = set(campaign.members.values_list("case_id", flat=True))
        material = {case: _cortex_material(case) for case in Case.objects.filter(id__in=stored).order_by("id")}
        for case, found in material.items():
            if found is None:
                self.stdout.write(f"case {case.id}: skipped, no successful Cortex AI report")
        replayable = [case for case, found in material.items() if found is not None]
        profile = current_profile()
        if len(replayable) < profile.min_members:
            raise CommandError(
                f"cannot replay {ref}: {len(replayable)} of {len(stored)} members have a successful "
                f"Cortex AI report, {profile.min_members} needed"
            )

        scratch = dataclasses.replace(
            profile, collection_name=f"{profile.collection_name}__replay_{secrets.token_hex(4)}"
        )
        final, trigger, seen = None, None, set()
        try:
            # detect_campaign wants no outer atomic because its rows would commit after its lock
            # is released; these rows never commit.
            with transaction.atomic():
                # Otherwise the member guard in detect_campaign stops every replayed case.
                CampaignMember.objects.filter(campaign=campaign).delete()
                collection = open_collection(scratch)
                for case in replayable:
                    found = detect_campaign(case, *material[case], scratch, collection)
                    if found is None:
                        doc = collection.get(ids=[f"case-{case.id}"]).get("ids")
                        outcome = "stored" if doc else "not stored"
                    else:
                        outcome = "joined" if found.id in seen else "created"
                        seen.add(found.id)
                        final, trigger = found, case.id
                    self.stdout.write(f"case {case.id}: {outcome}")
                replayed = set(final.members.values_list("case_id", flat=True)) if final else set()
                transaction.set_rollback(True)
        finally:
            self._drop(scratch.collection_name)

        missing, extra, stored_trigger = sorted(stored - replayed), sorted(replayed - stored), max(stored)
        if missing or extra or trigger != stored_trigger:
            raise CommandError(
                f"campaign {ref} differs: missing case ids {missing}, extra case ids {extra}, "
                f"trigger case {trigger} (stored {stored_trigger})"
            )
        self.stdout.write(f"MATCH: campaign {ref}, {len(stored)} members, trigger case {trigger}")

    def _drop(self, name: str) -> None:
        try:
            get_chroma_client().delete_collection(name)
        except Exception as exc:  # noqa: BLE001 -- must not hide the replay's own result or error
            self.stderr.write(f"scratch collection {name} was not dropped: {type(exc).__name__}")
