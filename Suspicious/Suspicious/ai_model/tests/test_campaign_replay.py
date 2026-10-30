"""ai_model_campaign_replay: a stored campaign's members, replayed from their Cortex AI reports
through the connector's detection, against a scratch collection and inside a rolled-back
transaction. The stored campaigns are built from rows, as the Cortex path left them."""
import math
from io import StringIO
from unittest.mock import MagicMock, patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from case_handler.models import Campaign, CampaignMember, Case
from connectors.contrib.ai_model.campaigns import CampaignStoreUnavailable
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob

M = "ai_model.management.commands.ai_model_campaign_replay"
HEADERS = (
    "defaultdict(<class 'list'>, {'From': ['HR <hr@evil.example>'], "
    "'Subject': ['=?utf-8?q?Verify_payroll?=']})"
)


def _unit(angle):
    """A unit vector: two of them are at cosine distance 1 - cos(angle difference)."""
    return [math.cos(angle), math.sin(angle), 0.0]


def _cosine_distance(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    return 1 - dot / (math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b)))


class CosineCollection:
    """The Chroma calls detection makes, in memory, with real cosine distances."""

    def __init__(self):
        self.docs = {}

    def get(self, ids=None, include=None):
        ids = [i for i in (ids or []) if i in self.docs]
        return {"ids": ids, "metadatas": [self.docs[i]["metadata"] for i in ids]}

    def add(self, ids, embeddings, metadatas, documents=None):
        self.docs[ids] = {"embedding": embeddings, "metadata": dict(metadatas[0]), "document": documents}

    def update(self, ids, metadatas):
        self.docs[ids]["metadata"] = dict(metadatas)

    def query(self, query_embeddings, where, n_results, include):
        hits = sorted(
            (_cosine_distance(query_embeddings, doc["embedding"]), i)
            for i, doc in self.docs.items()
            if doc["metadata"]["classification"] == where["classification"]
        )[:n_results]
        return {
            "ids": [[i for _, i in hits]],
            "distances": [[d for d, _ in hits]],
            "embeddings": [[self.docs[i]["embedding"] for _, i in hits]],
            "metadatas": [[self.docs[i]["metadata"] for _, i in hits]],
            "documents": [[self.docs[i]["document"] for _, i in hits]],
        }


def _case():
    user, _ = get_user_model().objects.get_or_create(username="rep", defaults={"email": "r@e.c"})
    return Case.objects.create(reporter=user, description="t")


def _cortex_ai_report(case, embedding):
    """The AI_Mail analyzer's report as Cortex stored it: numbers as strings, headers as the
    repr of a defaultdict, the embedding as a string."""
    analyzer, _ = Analyzer.objects.get_or_create(
        name="AI_Mail_Analyzer_2_0", defaults={"analyzer_cortex_id": "ai-mail"}
    )
    full = {
        "classification": "DANGEROUS", "sub_classification": "CLONE",
        "malscore": "9.75", "confidence": "0.96",
        "report": {
            "analyzed_mail_content": "Your payroll account is locked",
            "analyzed_mail_headers": HEADERS,
            "email_embedding": str(embedding),
        },
    }
    report = AnalyzerReport.objects.create(
        cortex_job_id=f"job-{case.id}", type="mail", status="Success", analyzer=analyzer,
        level="malicious", confidence=0.96, score=9.75,
        report_summary={}, report_taxonomy={}, report_full=full,
    )
    CaseAnalyzerJob.objects.create(
        case=case, cortex_job_id=f"job-{case.id}", analyzer=analyzer,
        analyzer_report=report, status=CaseAnalyzerJob.STATUS_SUCCESS,
    )


def _stored_campaign(angles):
    """A campaign with one member per angle, in that id order; None means no Cortex report."""
    campaign = Campaign.objects.create(title="Verify payroll")
    cases = []
    for angle in angles:
        case = _case()
        if angle is not None:
            _cortex_ai_report(case, _unit(angle))
        CampaignMember.objects.create(campaign=campaign, case=case)
        cases.append(case)
    return campaign, cases


def _row_counts():
    return {
        model._meta.label: model._default_manager.count()
        for model in apps.get_models()
        if model._meta.managed and not model._meta.proxy
    }


class CampaignReplayTest(TestCase):
    def setUp(self):
        cache.delete("campaign:detect")
        self.coll = CosineCollection()
        self.chroma = MagicMock()
        patchers = [
            patch(f"{M}.open_collection", return_value=self.coll),
            patch(f"{M}.get_chroma_client", return_value=self.chroma),
        ]
        self.opened = patchers[0].start()
        for patcher in patchers[1:]:
            patcher.start()
        for patcher in patchers:
            self.addCleanup(patcher.stop)

    def _run(self, ref):
        """The command's output and the CommandError it raised, if any."""
        out = StringIO()
        try:
            call_command("ai_model_campaign_replay", ref, stdout=out)
        except CommandError as exc:
            return out.getvalue(), str(exc)
        return out.getvalue(), None

    def _members(self, campaign):
        return set(campaign.members.values_list("case_id", flat=True))

    def test_a_campaign_built_by_the_old_path_replays_to_a_match(self):
        campaign, cases = _stored_campaign([0, 0.05, 0.1, 0.15, 0.2])
        out, error = self._run(campaign.ref)
        self.assertIsNone(error)
        a, b, c, d, e = (case.id for case in cases)
        self.assertEqual(out.splitlines(), [
            f"case {a}: stored",
            f"case {b}: stored",
            f"case {c}: stored",
            f"case {d}: created",
            f"case {e}: joined",
            f"MATCH: campaign {campaign.ref}, 5 members, trigger case {e}",
        ])

    def test_a_member_with_a_distant_embedding_is_reported_as_a_difference_and_fails(self):
        campaign, cases = _stored_campaign([0, 0.05, math.pi / 2, 0.1, 0.15])
        out, error = self._run(campaign.ref)
        self.assertIn(f"case {cases[2].id}: stored", out)
        self.assertIn(f"case {cases[4].id}: created", out)
        self.assertNotIn("MATCH", out)
        self.assertIn(f"missing case ids [{cases[2].id}]", error)
        self.assertIn("extra case ids []", error)
        self.assertEqual(self._members(campaign), {case.id for case in cases})

    def test_the_replay_changes_no_rows(self):
        campaign, cases = _stored_campaign([0, 0.05, 0.1, 0.15, 0.2])
        before = _row_counts()
        out, error = self._run(campaign.ref)
        self.assertIsNone(error)
        self.assertEqual(_row_counts(), before)
        self.assertEqual(list(Campaign.objects.values_list("ref", flat=True)), [campaign.ref])
        self.assertEqual(self._members(campaign), {case.id for case in cases})

    def test_a_member_without_a_cortex_report_is_skipped(self):
        campaign, cases = _stored_campaign([None, 0, 0.05, 0.1, 0.15])
        out, error = self._run(campaign.ref)
        self.assertIn(f"case {cases[0].id}: skipped, no successful Cortex AI report", out)
        self.assertIn(f"case {cases[4].id}: created", out)
        # It cannot come out of the replay, so the campaigns differ.
        self.assertIn(f"missing case ids [{cases[0].id}]", error)
        self.assertEqual(self._members(campaign), {case.id for case in cases})

    def test_too_few_replayable_members_fails(self):
        campaign, cases = _stored_campaign([None, None, 0])
        before = _row_counts()
        out, error = self._run(campaign.ref)
        self.assertIn("cannot replay", error)
        self.assertIn(f"case {cases[1].id}: skipped", out)
        self.opened.assert_not_called()
        self.assertEqual(_row_counts(), before)

    def test_an_unknown_campaign_fails(self):
        out, error = self._run("CMP-nope")
        self.assertIn("unknown campaign", error)
        self.opened.assert_not_called()

    def test_the_scratch_collection_is_dropped_when_the_replay_raises(self):
        campaign, cases = _stored_campaign([0, 0.05, 0.1, 0.15, 0.2])
        with patch(f"{M}.detect_campaign", side_effect=CampaignStoreUnavailable("store down")):
            with self.assertRaises(CampaignStoreUnavailable):
                self._run(campaign.ref)
        scratch = self.opened.call_args.args[0].collection_name
        self.chroma.delete_collection.assert_called_once_with(scratch)
        self.assertEqual(self._members(campaign), {case.id for case in cases})

    def test_the_live_collection_is_never_opened_or_dropped(self):
        campaign, _ = _stored_campaign([0, 0.05, 0.1, 0.15, 0.2])
        self._run(campaign.ref)
        self.opened.assert_called_once()
        scratch = self.opened.call_args.args[0].collection_name
        self.assertRegex(scratch, r"^suspicious_mails__replay_[0-9a-f]+$")
        self.chroma.delete_collection.assert_called_once_with(scratch)
        self.chroma.get_or_create_collection.assert_not_called()
