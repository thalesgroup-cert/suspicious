"""ai_model_campaign_replay: a stored campaign's members, and the campaign-less dangerous mails
between them, replayed from their Cortex AI reports through the connector's detection, against
a collection in an in-process Chroma and inside a rolled-back transaction. The stored campaigns
are built from rows, as the Cortex path left them.

CampaignReplayTest pins the logic over an in-memory cosine fake; RealChromaReplayTest runs the
same command over the real ephemeral Chroma."""
import dataclasses
import importlib
import math
import re
from io import StringIO
from unittest import skipIf
from unittest.mock import MagicMock, patch

try:
    import chromadb
except ImportError:  # pragma: no cover -- requirements.txt pins chromadb; reported as a skip
    chromadb = None

from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from ai_model.campaign_profile import current_profile
from case_handler.models import Campaign, CampaignMember, Case
from connectors.contrib.ai_model.campaigns import CampaignStoreUnavailable
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from score_process.score_utils.chromadb_utils import get_suspicious_collection

M = "ai_model.management.commands.ai_model_campaign_replay"
SCRATCH = re.compile(r"^suspicious_mails__replay_[0-9a-f]+$")
HEADERS = (
    "defaultdict(<class 'list'>, {'From': ['HR <hr@evil.example>'], "
    "'Subject': ['=?utf-8?q?Verify_payroll?=']})"
)
NEAR = [0, 0.05, 0.1, 0.15, 0.2]


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


def _cortex_ai_report(case, embedding, classification, malscore, confidence):
    """The AI_Mail analyzer's report as Cortex stored it: numbers as strings, headers as the
    repr of a defaultdict, the embedding as a string."""
    analyzer, _ = Analyzer.objects.get_or_create(
        name="AI_Mail_Analyzer_2_0", defaults={"analyzer_cortex_id": "ai-mail"}
    )
    full = {
        "classification": classification, "sub_classification": "CLONE",
        "malscore": malscore, "confidence": confidence,
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


def _mail_case(angle=None, campaign=None, classification="DANGEROUS", malscore="9.75", confidence="0.96"):
    """The next case in id order: with a Cortex AI report unless ``angle`` is None, a member of
    ``campaign`` when given."""
    case = _case()
    if angle is not None:
        _cortex_ai_report(case, _unit(angle), classification, malscore, confidence)
    if campaign is not None:
        CampaignMember.objects.create(campaign=campaign, case=case)
    return case


def _stored_campaign(angles):
    """A campaign with one member per angle, in that id order; None means no Cortex report."""
    campaign = Campaign.objects.create(title="Verify payroll")
    return campaign, [_mail_case(angle, campaign) for angle in angles]


def _campaign_around(make_between):
    """A campaign of five members at angles 0 to 0.2, with whatever ``make_between()`` makes
    between its third and fourth member in id order: (campaign, members, what it returned)."""
    campaign = Campaign.objects.create(title="Verify payroll")
    members = [_mail_case(angle, campaign) for angle in (0, 0.05, 0.1)]
    between = make_between()
    members += [_mail_case(angle, campaign) for angle in (0.15, 0.2)]
    return campaign, members, between


def _row_counts():
    return {
        model._meta.label: model._default_manager.count()
        for model in apps.get_models()
        if model._meta.managed and not model._meta.proxy
    }


def _lines(out, case):
    return [line for line in out.splitlines() if line.startswith((f"case {case.id}:", f"case {case.id} ("))]


def _match_line(campaign, members):
    return (
        f"MATCH: campaign {campaign.ref}, {members} members (membership only: the campaign_updated "
        "payload also depends on the case that triggered detection, and id order only "
        "approximates the original finalisation order)"
    )


class _Replay(TestCase):
    def setUp(self):
        cache.delete("campaign:detect")

    def _run(self, ref):
        """stdout, stderr and the CommandError message (None when the command succeeded)."""
        out, err = StringIO(), StringIO()
        try:
            call_command("ai_model_campaign_replay", ref, stdout=out, stderr=err)
        except CommandError as exc:
            return out.getvalue(), err.getvalue(), str(exc)
        return out.getvalue(), err.getvalue(), None

    def _members(self, campaign):
        return set(campaign.members.values_list("case_id", flat=True))


class CampaignReplayTest(_Replay):
    def setUp(self):
        super().setUp()
        self.coll = CosineCollection()
        self.chroma = MagicMock()
        self.chroma.get_or_create_collection.return_value = self.coll
        self.ephemeral = patch(f"{M}.ephemeral_client", return_value=self.chroma).start()
        self.addCleanup(patch.stopall)

    def _scratch_name(self):
        return self.chroma.get_or_create_collection.call_args.kwargs["name"]

    def test_a_campaign_stored_as_rows_replays_to_a_match(self):
        campaign, cases = _stored_campaign(NEAR)
        with patch("connectors.dispatch.emit") as emit:
            out, err, error = self._run(campaign.ref)
        self.assertIsNone(error)
        emit.assert_not_called()
        a, b, c, d, e = (case.id for case in cases)
        self.assertEqual(out.splitlines(), [
            f"case {a}: stored",
            f"case {b}: stored",
            f"case {c}: stored",
            f"case {d}: created",
            f"case {e}: joined",
            _match_line(campaign, 5),
        ])

    def test_a_member_with_a_distant_embedding_is_reported_as_a_difference_and_fails(self):
        campaign, cases = _stored_campaign([0, 0.05, math.pi / 2, 0.1, 0.15])
        out, err, error = self._run(campaign.ref)
        self.assertEqual(_lines(out, cases[2]), [f"case {cases[2].id}: stored"])
        self.assertEqual(_lines(out, cases[4]), [f"case {cases[4].id}: created"])
        self.assertNotIn("MATCH", out)
        self.assertIn(f"missing case ids [{cases[2].id}]", error)
        self.assertIn("extra case ids []", error)
        self.assertEqual(self._members(campaign), {case.id for case in cases})

    def test_a_near_mail_in_no_campaign_between_the_members_shows_up_as_extra_and_fails(self):
        campaign, members, near = _campaign_around(lambda: _mail_case(0.12))
        out, err, error = self._run(campaign.ref)
        self.assertEqual(_lines(out, near), [f"case {near.id} (not a member): created"])
        self.assertIn("missing case ids []", error)
        self.assertIn(f"extra case ids [{near.id}]", error)
        self.assertFalse(CampaignMember.objects.filter(case=near).exists())
        self.assertEqual(self._members(campaign), {case.id for case in members})

    def test_a_far_mail_in_no_campaign_between_the_members_is_replayed_and_still_matches(self):
        campaign, members, far = _campaign_around(lambda: _mail_case(math.pi / 2))
        out, err, error = self._run(campaign.ref)
        self.assertIsNone(error)
        self.assertEqual(_lines(out, far), [f"case {far.id} (not a member): stored"])
        self.assertIn(_match_line(campaign, 5), out)

    def test_a_near_mail_of_another_campaign_is_not_replayed(self):
        other = Campaign.objects.create(title="Other")
        campaign, members, elsewhere = _campaign_around(lambda: _mail_case(0.12, other))
        out, err, error = self._run(campaign.ref)
        self.assertIsNone(error)
        self.assertEqual(_lines(out, elsewhere), [])
        self.assertIn(_match_line(campaign, 5), out)
        self.assertEqual(self._members(other), {elsewhere.id})

    def test_a_mail_in_no_campaign_without_a_report_or_not_dangerous_is_ignored(self):
        campaign, members, (no_report, safe) = _campaign_around(
            lambda: (_mail_case(None), _mail_case(0.12, classification="SAFE"))
        )
        out, err, error = self._run(campaign.ref)
        self.assertIsNone(error)
        self.assertEqual(_lines(out, no_report), [])
        self.assertEqual(_lines(out, safe), [])
        self.assertIn(_match_line(campaign, 5), out)

    def test_a_near_mail_outside_the_member_id_window_is_not_replayed_and_still_matches(self):
        before = _mail_case(0.02)
        campaign, cases = _stored_campaign(NEAR)
        after = _mail_case(0.12)
        out, err, error = self._run(campaign.ref)
        self.assertIsNone(error)
        self.assertEqual(_lines(out, before), [])
        self.assertEqual(_lines(out, after), [])
        self.assertIn(_match_line(campaign, 5), out)

    def test_the_replay_changes_no_rows(self):
        campaign, members, _ = _campaign_around(lambda: _mail_case(0.12))  # joins in the replay, undone
        before = _row_counts()
        out, err, error = self._run(campaign.ref)
        self.assertIn("extra case ids", error)
        self.assertEqual(_row_counts(), before)
        self.assertEqual(list(Campaign.objects.values_list("ref", flat=True)), [campaign.ref])
        self.assertEqual(self._members(campaign), {case.id for case in members})

    def test_a_member_without_a_cortex_report_is_skipped(self):
        campaign, cases = _stored_campaign([None, 0, 0.05, 0.1, 0.15])
        out, err, error = self._run(campaign.ref)
        self.assertEqual(_lines(out, cases[0]), [f"case {cases[0].id}: skipped, no successful Cortex AI report"])
        self.assertEqual(_lines(out, cases[4]), [f"case {cases[4].id}: created"])
        # It cannot come out of the replay, so the campaigns differ.
        self.assertIn(f"missing case ids [{cases[0].id}]", error)
        self.assertEqual(self._members(campaign), {case.id for case in cases})

    def test_a_member_with_a_non_numeric_score_or_confidence_is_skipped_as_unusable(self):
        campaign = Campaign.objects.create(title="Verify payroll")
        members = [_mail_case(angle, campaign) for angle in (0, 0.05, 0.1)]
        bad_score = _mail_case(0.12, campaign, malscore="n/a")
        bad_confidence = _mail_case(0.14, campaign, confidence="high")
        last = _mail_case(0.15, campaign)
        out, err, error = self._run(campaign.ref)
        for case in (bad_score, bad_confidence):
            self.assertEqual(_lines(out, case), [f"case {case.id}: skipped, unusable Cortex AI report"])
        self.assertEqual(_lines(out, last), [f"case {last.id}: created"])
        self.assertIn(f"missing case ids [{bad_score.id}, {bad_confidence.id}]", error)

    def test_too_few_replayable_members_fails(self):
        campaign, cases = _stored_campaign([None, None, 0])
        before = _row_counts()
        out, err, error = self._run(campaign.ref)
        self.assertIn("cannot replay", error)
        self.assertIn(f"case {cases[1].id}: skipped", out)
        self.ephemeral.assert_not_called()
        self.assertEqual(_row_counts(), before)

    def test_no_replayable_member_fails_even_when_no_member_is_needed(self):
        campaign, _ = _stored_campaign([None, None])
        profile = dataclasses.replace(current_profile(), min_members=0)
        with patch(f"{M}.current_profile", return_value=profile):
            out, err, error = self._run(campaign.ref)
        self.assertIn("cannot replay", error)
        self.ephemeral.assert_not_called()

    def test_an_unknown_campaign_fails(self):
        out, err, error = self._run("CMP-nope")
        self.assertIn("unknown campaign", error)
        self.ephemeral.assert_not_called()

    def test_a_store_failure_in_detection_fails_naming_the_case_and_deletes_the_scratch_collection(self):
        campaign, cases = _stored_campaign(NEAR)
        with patch(f"{M}.detect_campaign", side_effect=CampaignStoreUnavailable("campaign lock timed out")):
            out, err, error = self._run(campaign.ref)
        self.assertEqual(error, f"case {cases[0].id}: campaign lock timed out")
        self.chroma.delete_collection.assert_called_once_with(self._scratch_name())
        self.assertEqual(self._members(campaign), {case.id for case in cases})

    def test_a_failed_delete_of_the_scratch_collection_fails_the_command(self):
        campaign, _ = _stored_campaign(NEAR)
        self.chroma.delete_collection.side_effect = RuntimeError("delete failed")
        out, err, error = self._run(campaign.ref)
        self.assertEqual(error, f"could not delete the in-process collection {self._scratch_name()}: RuntimeError")
        self.assertNotIn("MATCH", out)

    def test_the_scratch_collection_is_shaped_like_the_live_one_and_deleted(self):
        campaign, _ = _stored_campaign(NEAR)
        self._run(campaign.ref)
        self.ephemeral.assert_called_once()
        self.chroma.get_or_create_collection.assert_called_once_with(
            name=self._scratch_name(), metadata={"hnsw:space": "cosine"}
        )
        self.assertRegex(self._scratch_name(), SCRATCH)
        self.chroma.delete_collection.assert_called_once_with(self._scratch_name())


@skipIf(chromadb is None, "chromadb cannot be imported, so there is no in-process Chroma to replay on")
class RealChromaReplayTest(_Replay):
    """The command over the real in-process Chroma: real add, get, update and cosine query."""

    def _collections(self):
        return [c.name for c in importlib.import_module(M).ephemeral_client().list_collections()]

    def test_a_campaign_with_a_far_mail_between_its_members_matches(self):
        campaign, members, far = _campaign_around(lambda: _mail_case(math.pi / 2))
        out, err, error = self._run(campaign.ref)
        self.assertIsNone(error)
        self.assertEqual(out.splitlines(), [
            f"case {members[0].id}: stored",
            f"case {members[1].id}: stored",
            f"case {members[2].id}: stored",
            f"case {far.id} (not a member): stored",
            f"case {members[3].id}: created",
            f"case {members[4].id}: joined",
            _match_line(campaign, 5),
        ])

    def test_a_near_mail_in_no_campaign_shows_up_as_extra(self):
        campaign, members, near = _campaign_around(lambda: _mail_case(0.12))
        out, err, error = self._run(campaign.ref)
        self.assertEqual(_lines(out, near), [f"case {near.id} (not a member): created"])
        self.assertIn("missing case ids []", error)
        self.assertIn(f"extra case ids [{near.id}]", error)

    def test_two_replays_in_one_process_do_not_see_each_others_documents(self):
        campaign, _ = _stored_campaign(NEAR)
        first, _, first_error = self._run(campaign.ref)
        second, _, second_error = self._run(campaign.ref)
        self.assertIsNone(first_error)
        self.assertIsNone(second_error)
        self.assertEqual(second, first)

    def test_the_http_chroma_is_never_used_and_nothing_persists(self):
        module = importlib.import_module(M)
        self.assertFalse({"get_chroma_client", "open_collection"} & set(vars(module)))
        campaign, _ = _stored_campaign(NEAR)
        with patch("chromadb.HttpClient") as http_client, \
                patch("common.clients.get_chroma_client") as http, \
                patch("connectors.contrib.ai_model.campaigns.get_chroma_client") as campaigns_http, \
                patch("connectors.contrib.ai_model.campaigns.open_collection") as live, \
                patch(f"{M}.get_suspicious_collection", wraps=get_suspicious_collection) as made:
            out, err, error = self._run(campaign.ref)
        self.assertIsNone(error)
        for mock in (http_client, http, campaigns_http, live):
            mock.assert_not_called()
        self.assertRegex(made.call_args.args[1], SCRATCH)
        self.assertFalse([name for name in self._collections() if SCRATCH.match(name)])
