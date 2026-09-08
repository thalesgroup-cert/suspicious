"""
Analyzer report lifecycle: execution, persistence, and querying.
"""
import logging

from django.db.models import Max

from cortex_job.models import AnalyzerReport
from .utils import dump_model

update_cases_logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")


class CortexAnalyzerReports:
    """Handles persistence and lifecycle of analyzer reports."""

    # ── public pipeline entry point ───────────────────────────────────────

    @staticmethod
    def get_report(case) -> None:
        """
        Score a case end-to-end: collect signals (which also persists
        analyzer reports), compute the verdict, and apply it (persist,
        notify, KPI).
        """
        from cortex_job.cortex_utils.cortex_and_job_management import CortexJobManager
        from score_process.scoring.collect import collect_signals
        from score_process.scoring.engine import score_case
        from score_process.scoring.apply import apply_verdict

        if not case:
            update_cases_logger.warning("get_report called with no case.")
            return

        try:
            if getattr(case, "observable_group_id", None):
                from score_process.scoring.apply import finalise_ioc_group
                finalise_ioc_group(case)
                update_cases_logger.info(
                    "get_report: case %s → IOC-road categorical finalise", case.id
                )
                return

            mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail else None
            if mail:
                # AI classification is supplementary — never let a bug or
                # transient failure in here block the scoring pass below
                # (previously it could: an unhandled exception here used to
                # propagate to the outer except and skip collect_signals /
                # score_case / apply_verdict entirely, silently leaving
                # every mail case's verdict at its default Inconclusive).
                try:
                    CortexJobManager().manage_ai_jobs(case)
                except Exception as exc:
                    update_cases_logger.error(
                        "get_report: manage_ai_jobs failed for case %s: %s",
                        case.id, exc, exc_info=True,
                    )

            signals, ai, deny_listed, ai_missing, deny_reason = collect_signals(case)
            verdict = score_case(signals, ai, deny_listed, ai_missing, deny_reason)

            # Embedded-observable escalation (mail road): every embedded
            # observable of the mail is scored on its own analyzer reports via
            # the trust-weighted categorical engine; the mail band is raised to
            # the worst embedded band and the analyzers' rationale folded in.
            # (Flag OFF → _apply_derived_escalation, the Phase B behaviour.)
            if mail:
                verdict = CortexAnalyzerReports._apply_embedded_escalation(case, mail, verdict)

            apply_verdict(case, verdict)

            update_cases_logger.info(
                "get_report: case %s → %s (score=%s conf=%s, %d/%d malicious).",
                case.id, verdict.result, verdict.final_score,
                verdict.final_confidence, verdict.n_malicious, verdict.n_scored,
            )

        except Exception as exc:
            update_cases_logger.error(
                "get_report: error scoring case %s: %s", case.id, exc, exc_info=True
            )

    @staticmethod
    def _apply_embedded_escalation(case, mail, verdict):
        """Score every embedded observable of `mail` on its own analyzer reports
        via the trust-weighted categorical engine; raise the mail band to the
        worst embedded band and fold the analyzers' rationale in. Writes
        per-observable ioc_* (global) and per-MailArtifact artifact_*
        (case-scoped) levels.

        Flag `scoring.mail_embedded_categorical` default-ON — only an explicit
        stored `False` routes back to the Phase B `_apply_derived_escalation`
        (get_config returns None, not the default, for an unset warm-cache key).
        """
        from dataclasses import replace
        from settings.config import get_config
        if get_config("scoring.mail_embedded_categorical") is False:
            return CortexAnalyzerReports._apply_derived_escalation(case, mail, verdict)

        from case_handler.models import Result
        from score_process.scoring.observable_collect import mail_observable_reports
        from score_process.scoring.observable_engine import score_observable
        from score_process.scoring.sources import source_verdict_from_report
        from score_process.scoring.engine import mail_band_escalation
        from score_process.scoring.bands import (
            _BAND_ORDER, _BAND_RANK, _BAND_TO_IOC_LEVEL, _DERIVED_SCORE,
            _STICKY_IOC_LEVELS,
        )
        from cortex_job.cortex_utils.derived_observables import score_derived_observables

        # keep DerivedObservable.child_band / escalation_note fresh for the chip
        # UI — its return value is no longer used for the band merge.
        score_derived_observables(case)

        embedded, rationale_lines = [], []
        for m_art, obj, _field, reports in mail_observable_reports(mail):
            seen, svs = set(), []
            for r in reports:
                if r.analyzer_id in seen:
                    continue
                seen.add(r.analyzer_id)
                svs.append(source_verdict_from_report(r))
            if not svs:
                continue
            v = score_observable(svs)
            embedded.append(v)
            rationale_lines.extend(v.rationale)

            ioc_level = _BAND_TO_IOC_LEVEL.get(v.band, "info")
            score = _DERIVED_SCORE.get(v.band, 5)
            # A sticky marker (deny/allow-list) skips the WHOLE re-score, not
            # just the level string — deliberate departure from spec §5's
            # literal "write score/confidence unconditionally" (matches the
            # Phase B IOC-road final-review guidance).
            if getattr(obj, "ioc_level", "info") not in _STICKY_IOC_LEVELS:
                obj.ioc_level = ioc_level
                obj.ioc_score = score
                obj.ioc_confidence = v.confidence
                obj.save(update_fields=["ioc_level", "ioc_score", "ioc_confidence"])

            if m_art.artifact_level not in _STICKY_IOC_LEVELS:
                m_art.artifact_level = ioc_level
                m_art.artifact_score = score
                m_art.artifact_confidence = v.confidence
                m_art.save(update_fields=[
                    "artifact_level", "artifact_score", "artifact_confidence"])

        if not embedded:
            return verdict

        note = "; ".join(rationale_lines[:5]) or None
        worst = max(embedded, key=lambda v: _BAND_ORDER.get(v.band, 0))
        # A body-less mail scores Result.FAILURE (score_case has no scorable
        # signal). Only rebase to Inconclusive when the embedded evidence
        # actually raises the band (Suspicious/Dangerous) — an all-Safe/no-data
        # body-less mail stays FAILURE.
        base = replace(verdict, result=Result.INCONCLUSIVE) \
            if verdict.result == Result.FAILURE and _BAND_RANK.get(worst.band, 0) > 0 \
            else verdict
        return mail_band_escalation(base, embedded, note=note)

    @staticmethod
    def _apply_derived_escalation(case, mail, verdict):
        """Escalate the mail case band and bump parent MailArtifact levels for
        any derived child that scored strictly above its parent.

        Flag-OFF fallback for `_apply_embedded_escalation` (Phase B behaviour)."""
        from cortex_job.cortex_utils.derived_observables import (
            score_derived_observables, _MAIL_JOIN,
        )
        from score_process.scoring.engine import mail_band_escalation
        from score_process.scoring.observable_engine import ObservableVerdict
        from mail_feeder.models import MailArtifact

        escalations = score_derived_observables(case)
        if not escalations:
            return verdict

        rank = {"Suspicious": 1, "Dangerous": 2}
        worst_band, note, _conf = max(escalations.values(), key=lambda bn: rank.get(bn[0], 0))
        verdict = mail_band_escalation(
            verdict, [ObservableVerdict(worst_band, 100, None, {}, [])], note=note
        )

        # mirror _STICKY_IOC_LEVELS: an allow/deny-listed artifact keeps its level
        sticky = {"critical", "SAFE-ALLOW_LISTED"}
        ioc_level = {"Suspicious": "suspicious", "Dangerous": "malicious"}
        for (ptype, pid), (band, _note, _conf) in escalations.items():
            spec = _MAIL_JOIN.get(ptype)
            if spec is None:
                continue
            _join_cls, fk_attr, _art_type, join_field = spec
            (MailArtifact.objects
             .filter(mail=mail, **{f"{fk_attr}__{join_field}_id": pid})
             .exclude(artifact_level__in=sticky)
             .update(artifact_level=ioc_level[band]))
        return verdict

    # ── report processing helpers ─────────────────────────────────────────

    @staticmethod
    def process_analyzer_reports(reports, analyzer_reports, artifact_value, case_id):
        """Process Cortex job outputs and append to the shared reports list."""
        failure_count = 0
        update_cases_logger.info(
            "[reports] Processing %d analyzer reports.", len(analyzer_reports)
        )

        for report in analyzer_reports:
            try:
                if report.status == "Success":
                    CortexAnalyzerReports.create_and_save_report(
                        report, artifact_value, case_id
                    )
                elif report.status == "Failure":
                    failure_count += CortexAnalyzerReports.handle_failure(report)

                update_cases_logger.info(
                    "Processed report id=%s status=%s score=%s confidence=%s.",
                    report.id, report.status, report.score, report.confidence,
                )
                reports.append(report)

            except Exception as exc:
                update_cases_logger.error(
                    "Error processing analyzer report id=%s: %s",
                    getattr(report, "id", "?"), exc, exc_info=True,
                )

        return failure_count

    @staticmethod
    def create_and_save_report(report, artifact_value, case_id):
        """Run the resolved parser for a finished job and write scoring fields.

        PENDING (job not finished) → leave the row untouched for the next poll.
        Only update the four scoring columns — prevents overwriting foreign keys
        or timestamps another process may have changed. AnalyzerReport has no
        `details` column; raw payload is already in report_full / report_summary.
        """
        from .registry import registry
        from .result import PENDING
        try:
            update_cases_logger.info(
                "Creating result for artifact=%r analyzer=%s.",
                artifact_value, report.analyzer.name,
            )

            parser_cls = registry.resolve(report.analyzer)
            parser = parser_cls(
                analyzer_name=report.analyzer.name,
                data=artifact_value,
                data_type=report.type,
                case_id=case_id,
            )
            result = parser.run(report.report_summary, report.report_full, report.status)
            if result is PENDING:
                update_cases_logger.info(
                    "Report %s still pending — not scoring.", getattr(report, "id", "?"))
                return

            result_dict = dump_model(result)
            category = result_dict.get("category", "Unknown")
            if isinstance(category, list):
                category = ", ".join(str(c) for c in category)

            from score_process.scoring.enrichment.registry import enrich
            report.score      = result_dict.get("score",      0)
            report.confidence = result_dict.get("confidence", 0)
            report.category   = category
            report.level      = result_dict.get("level",    "info")
            report.enrichment = enrich(report)
            report.save(update_fields=["score", "confidence", "category", "level", "enrichment"])

        except Exception as exc:
            update_cases_logger.error(
                "Error saving analyzer report id=%s: %s",
                getattr(report, "id", "?"), exc, exc_info=True,
            )

    @staticmethod
    def handle_failure(report):
        """Record a failed analyzer execution with neutral/baseline scores."""
        report.score      = 5
        report.confidence = 0
        report.category   = "Failed task"
        report.level      = "info"
        report.save(update_fields=["score", "confidence", "category", "level"])
        return 1

    # ── queryset helpers ──────────────────────────────────────────────────

    @staticmethod
    def get_analyzer_reports_by_type_and_artifact(artifact_type, artifact):
        """
        Return the most-recent AnalyzerReport per analyzer for a given
        artifact, as an ORM QuerySet (not a list).

        The subquery stays inside the database — no Python list
        materialisation — so Django can combine it with further filters
        or prefetch_related calls from the caller without extra queries.

        Supported artifact types:
            file, hash, url, ip, domain, mail_body, mail_header, mailaddress
        """
        FIELD_MAP = {
            "file":        "file",
            "hash":        "hash",
            "url":         "url",
            "ip":          "ip",
            "domain":      "domain",
            "mail_body":   "mail_body",
            "mail_header": "mail_header",
            "mailaddress": "mail",
        }

        field_name = FIELD_MAP.get(artifact_type)
        if not field_name:
            update_cases_logger.warning(
                "get_analyzer_reports_by_type_and_artifact: unknown type %r.", artifact_type
            )
            return AnalyzerReport.objects.none()

        latest_id_subquery = (
            AnalyzerReport.objects
            .filter(**{field_name: artifact})
            .values("analyzer_id")
            .annotate(latest_id=Max("id"))
            .values("latest_id")
        )

        return AnalyzerReport.objects.filter(id__in=latest_id_subquery)

    @staticmethod
    def exclude_ai_analyzer(reports):
        """Drop the AI mail classifier's own report from a per-artifact
        report list before weighting.

        AI_Mail_Analyzer attaches its report to the mail archive's `file`
        (see cortex_and_job_management.manage_ai_jobs), and collect.py
        already surfaces that same score/confidence separately as the
        dedicated `ai` override signal (built from case.score_ai/
        confidence_ai). Leaving it inside this generic per-file weighted
        blend double-counts it — inflating base_conf enough to tie
        ai.confidence, which silences score_case()'s ai-override branch on
        a tie and lets the case fall back to the (possibly neutral) base
        score instead of the AI's actual verdict.
        """
        from cortex_job.cortex_utils.cortex_and_job_management import _get_cortex_config

        ai_name = _get_cortex_config().get("analyzers", {}).get("ai")
        if not ai_name:
            return list(reports)
        return [r for r in reports if r.analyzer.name != ai_name]