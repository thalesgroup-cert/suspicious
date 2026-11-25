import importlib

from django.apps import apps
from django.test import TestCase

from cortex_job.models import Analyzer


class AnalyzerSourceTests(TestCase):
    def test_new_analyzer_defaults_to_cortex_source(self):
        a = Analyzer.objects.create(name="X", analyzer_cortex_id="x1")
        self.assertEqual(a.source, "cortex")

    def test_migration_marks_provider_rows_ai_model(self):
        mod = importlib.import_module("cortex_job.migrations.0017_analyzer_source")
        Analyzer.objects.create(name="AI", analyzer_cortex_id="provider:AI")
        Analyzer.objects.create(name="Y", analyzer_cortex_id="y1")
        mod.mark_provider_rows(apps, None)
        self.assertEqual(Analyzer.objects.get(name="AI").source, "ai_model")
        self.assertEqual(Analyzer.objects.get(name="Y").source, "cortex")

    def test_migration_marks_the_ai_vote_row_by_name(self):
        from cortex_job.cortex_utils.cortex_and_job_management import ai_analyzer_name
        mod = importlib.import_module("cortex_job.migrations.0017_analyzer_source")
        Analyzer.objects.create(name=ai_analyzer_name(), analyzer_cortex_id="legacy-cortex-id")
        mod.mark_provider_rows(apps, None)
        self.assertEqual(Analyzer.objects.get(name=ai_analyzer_name()).source, "ai_model")
