"""Replay a campaign the Cortex AI path built through the ai_model connector's detection and
compare the members.

Read-only: it runs in a transaction that is always rolled back, against a collection in an
in-process Chroma that lives only as long as the command, and emits no event. The Chroma server
is never contacted: every embedding comes from the Cortex reports in the database. Safe to run
against production data."""
import secrets
from contextlib import contextmanager

import chromadb
from chromadb.config import Settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from ai_model.campaign_profile import current_profile
from ai_model.models import AiAssessment
from case_handler.models import Campaign, CampaignMember, Case
from connectors.contrib.ai_model.campaigns import CampaignStoreUnavailable, detect_campaign
from connectors.contrib.thehive.utils import parse_and_decode_defaultdict
from cortex_job.models import AnalyzerReport
from score_process.score_utils.chromadb_utils import get_suspicious_collection

_AI_PREFIX = "AI_Mail"


def ephemeral_client():
    """The in-process Chroma. Every caller builds it here: Chroma refuses a second client of the
    process with other settings."""
    return chromadb.EphemeralClient(settings=Settings(anonymized_telemetry=False))


@contextmanager
def _scratch_collection(name: str):
    """A collection made like the live one, in an in-process Chroma, deleted on exit. The
    in-process Chroma is shared by every client of the process, hence the unique name."""
    client = ephemeral_client()
    collection = get_suspicious_collection(client, name)
    try:
        yield collection
    finally:
        try:
            client.delete_collection(name)
        except Exception as exc:  # noqa: BLE001 -- the Chroma client's failures are many
            raise CommandError(
                f"could not delete the in-process collection {name}: {type(exc).__name__}"
            ) from exc


def _cortex_full(case_id: int) -> dict | None:
    """The newest successful Cortex AI report_full of the case, if it has a report section."""
    report = (
        AnalyzerReport.objects.filter(
            analyzer__name__startswith=_AI_PREFIX, case_jobs__case_id=case_id, status="Success",
        ).order_by("-id").first()
    )
    full = report.report_full if report else None
    return full if isinstance(full, dict) and isinstance(full.get("report"), dict) else None


def _material(case: Case, full: dict | None):
    """((assessment, text, headers), "") for detect_campaign, or (None, why the case is skipped).
    The assessment is never saved."""
    if full is None:
        return None, "no successful Cortex AI report"
    try:
        score = float(full.get("malscore") or 0)
        confidence = float(full.get("confidence") or 0) * 100
    except (TypeError, ValueError):
        return None, "unusable Cortex AI report"
    body = full["report"]
    try:
        headers = parse_and_decode_defaultdict(str(body.get("analyzed_mail_headers", "")))
    except Exception:  # noqa: BLE001 -- keep the raw value, as the Cortex path did
        headers = body.get("analyzed_mail_headers", "")
    assessment = AiAssessment(
        case=case,
        result=str(full.get("classification", "")),
        sub_class=str(full.get("sub_classification") or ""),
        score=score,
        confidence=confidence,
        campaign_embedding=str(body.get("email_embedding") or ""),
    )
    return (assessment, str(body.get("analyzed_mail_content") or ""), headers), ""


class Command(BaseCommand):
    help = (
        "Replay a stored campaign through the ai_model connector's campaign detection and compare "
        "the members. Replayed in case id order, from their Cortex AI reports: the campaign's members "
        "and every case between its lowest and highest member id that has a successful DANGEROUS "
        "Cortex AI report and is in no campaign, so a mail the new path would add shows up as extra. "
        "Compared: the members of the campaign the last stored member ends in; a missing or extra "
        "case id fails the command. MATCH is membership only: the campaign_updated payload also "
        "depends on the case that triggered detection, and id order only approximates the original "
        "finalisation order. An allow-list changed since the campaign formed can legitimately show "
        "up as an extra or missing case (the ids are printed so you can look). Changes nothing: the "
        "transaction is rolled back, no event is sent, and the mails are compared in an in-process "
        "Chroma that is deleted at the end (nothing persists; the Chroma server is never "
        "contacted). Deleting the campaign's member rows holds their row locks for the whole "
        "replay, so run it off-peak on a very large campaign."
    )

    def add_arguments(self, parser):
        parser.add_argument("campaign_ref", help="Campaign.ref of the campaign to replay")

    def handle(self, *args, **opts):
        ref = opts["campaign_ref"]
        campaign = Campaign.objects.filter(ref=ref).first()
        if campaign is None:
            raise CommandError(f"unknown campaign {ref!r}")
        stored = set(campaign.members.values_list("case_id", flat=True))
        profile = current_profile()

        fulls = {cid: _cortex_full(cid) for cid in stored}
        window = Case.objects.filter(
            id__gt=min(stored, default=0), id__lt=max(stored, default=0),
            campaign_membership__isnull=True,
            analyzer_jobs__analyzer_report__analyzer__name__startswith=_AI_PREFIX,
            analyzer_jobs__analyzer_report__status="Success",
        ).values_list("id", flat=True).distinct()
        for cid in window:
            full = _cortex_full(cid)
            if full and full.get("classification") == profile.trigger_class:
                fulls[cid] = full

        cases = Case.objects.in_bulk(list(fulls))
        replay = []
        for cid in sorted(fulls):
            label = f"case {cid}" if cid in stored else f"case {cid} (not a member)"
            material, why = _material(cases[cid], fulls[cid])
            if material is None:
                self.stdout.write(f"{label}: skipped, {why}")
            else:
                replay.append((cases[cid], label, material))
        replayable = [case.id for case, _, _ in replay if case.id in stored]
        needed = max(profile.min_members, 1)  # the comparison reads the last replayed member
        if len(replayable) < needed:
            raise CommandError(
                f"cannot replay {ref}: {len(replayable)} of {len(stored)} members have a usable "
                f"Cortex AI report, {needed} needed"
            )

        seen = set()
        scratch = f"{profile.collection_name}__replay_{secrets.token_hex(8)}"
        # detect_campaign wants no outer atomic because its rows would commit after its lock is
        # released; these rows never commit.
        with _scratch_collection(scratch) as collection, transaction.atomic():
            # Otherwise the member guard in detect_campaign stops every replayed case.
            CampaignMember.objects.filter(campaign=campaign).delete()
            for case, label, material in replay:
                try:
                    found = detect_campaign(case, *material, profile, collection)
                except CampaignStoreUnavailable as exc:
                    raise CommandError(f"case {case.id}: {exc}") from exc
                if found is None:
                    doc = collection.get(ids=[f"case-{case.id}"]).get("ids")
                    outcome = "stored" if doc else "not stored"
                else:
                    outcome = "joined" if found.id in seen else "created"
                    seen.add(found.id)
                self.stdout.write(f"{label}: {outcome}")
            landed = CampaignMember.objects.filter(case_id=max(replayable)).values_list(
                "campaign_id", flat=True
            ).first()
            replayed = set(
                CampaignMember.objects.filter(campaign_id=landed).values_list("case_id", flat=True)
            ) if landed else set()
            transaction.set_rollback(True)

        missing, extra = sorted(stored - replayed), sorted(replayed - stored)
        if missing or extra:
            raise CommandError(f"campaign {ref} differs: missing case ids {missing}, extra case ids {extra}")
        self.stdout.write(
            f"MATCH: campaign {ref}, {len(stored)} members (membership only: the campaign_updated "
            "payload also depends on the case that triggered detection, and id order only "
            "approximates the original finalisation order)"
        )
