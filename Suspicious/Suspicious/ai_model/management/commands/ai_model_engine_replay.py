"""ai_model_engine_replay: how much the scoring engine's verdicts move when the shadow's AI signal
replaces the live one (Plan F, Ruling F15). A sensitivity study, not an oracle.

Read-only: the non-AI signals are rebuilt from the ledger as backtest_scoring does, and the embedded
evidence step (which writes IOC levels) is left out, so both passes are simplified the same way and
only the AI signal differs. Writes no Case, ShadowResult or ledger row and never calls get_report.
Prints counts and statistics only: never mail text, subjects, addresses."""
import json
import statistics
from collections import Counter
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from connectors.registry import registry as connector_registry
from ai_model.models import AiAssessment, ModelVersion
from ai_model.shadow import flip_of
from case_handler.models import Case, Result
from connectors.contrib.ai_model.mailtext import mail_archive_for, read_archive_body
from score_process.management.commands.backtest_scoring import _signals_for
from score_process.scoring.collect import collect_votes
from score_process.scoring.engine import AiSignal, score_case

EPILOG = ("Operator step: with a real candidate loaded as shadow, run this on the last 30 days "
          "(--since-days 30 --limit 500) and record the figures. The first promotion waits for it.")


def _verdict(case, ai, missing):
    signals = _signals_for(case)
    try:
        votes = collect_votes(case, ai)
    except Exception:
        votes = ()
    return score_case(signals, ai, case.is_denylisted, missing, case.list_reason, votes=votes)


def _rate(verdicts):
    return round(sum(v.result == Result.INCONCLUSIVE for v in verdicts) / len(verdicts), 4) if verdicts else None


def _median(verdicts):
    return statistics.median(v.final_confidence for v in verdicts) if verdicts else None


class Command(BaseCommand):
    help = "Replay recent finalised mail cases with the live and the shadow AI signal (read-only)."
    epilog = EPILOG

    def create_parser(self, *args, **kwargs):
        parser = super().create_parser(*args, **kwargs)
        parser.epilog = EPILOG
        return parser

    def add_arguments(self, parser):
        parser.add_argument("version_id", help="the registry's current shadow version")
        parser.add_argument("--limit", type=int, default=200)
        parser.add_argument("--since-days", type=int, default=30)
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **opts):
        if not ModelVersion.objects.filter(
                version_id=opts["version_id"], status=ModelVersion.Status.SHADOW).exists():
            raise CommandError("that version is not the registry's shadow")
        client = connector_registry.instantiate("ai_model")._client()
        since = timezone.now() - timedelta(days=opts["since_days"])
        cases = (Case.objects.exclude(results="").filter(
            fileOrMail__mail__isnull=False, creation_date__gte=since).order_by("-id")
            .select_related("fileOrMail__mail"))
        matrix, before, after, skipped = Counter(), [], [], 0
        changed = critical = 0
        for case in cases.iterator():
            if len(before) >= opts["limit"]:
                break
            try:
                archive = mail_archive_for(case)
                body = read_archive_body(archive) if archive is not None else None
                if body is None:
                    raise ValueError
                shadow = client.classify(body, exclude_case_ids=[case.id], versions=["shadow"])
                shadow = shadow["results"]["shadow"]
                if "error" in shadow:
                    raise ValueError
                s_missing = shadow["class"] == AiAssessment.Result.INCONCLUSIVE
                s_conf = min(round(float(shadow["confidence"]) * 100), 100)
                s_ai = None if s_missing or not s_conf else AiSignal(score=round(float(shadow["score"])),
                                                                     confidence=s_conf)
            except Exception:   # a refused, failed or unreadable case: counted, never described
                skipped += 1
                continue
            missing = case.results_ai == Result.INCONCLUSIVE
            ai = None
            if case.confidence_ai and not missing:   # as collect_signals builds the live AI signal
                ai = AiSignal(score=case.score_ai or 0, confidence=min(round(case.confidence_ai), 100))
            live, would = _verdict(case, ai, missing), _verdict(case, s_ai, s_missing)
            before.append(live)
            after.append(would)
            matrix[f"{live.result}->{would.result}"] += 1
            flip = flip_of(live.result, would.result)
            changed += flip != "none"
            critical += flip == "critical"
        report = {
            "version": opts["version_id"], "replayed": len(before), "skipped": skipped,
            "changed": changed, "critical": critical, "matrix": dict(sorted(matrix.items())),
            "inconclusive_rate_before": _rate(before), "inconclusive_rate_after": _rate(after),
            "median_confidence_before": _median(before), "median_confidence_after": _median(after),
        }
        if opts["json"]:
            self.stdout.write(json.dumps(report))
            return
        for key in ("replayed", "skipped", "changed", "critical", "inconclusive_rate_before",
                    "inconclusive_rate_after", "median_confidence_before", "median_confidence_after"):
            self.stdout.write(f"{key.replace('_', ' ')}: {report[key]}".replace(" ", " ", 1))
        self.stdout.write("transition matrix (live -> shadow: count):")
        for k, n in report["matrix"].items():
            self.stdout.write(f"  {k}: {n}")
