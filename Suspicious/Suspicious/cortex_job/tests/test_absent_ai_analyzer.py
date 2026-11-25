"""The Cortex AI analyzer left the catalog, so a deployment may have no
integrations.cortex.analyzers.ai key (the example settings keep it: it names the AI vote's
Analyzer row). The code that reads it must work when the key is absent."""
from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase

from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
from tasp.tests.test_sync_cortex import _fake_cron_config

NO_AI = {"analyzers": {"header": "Mail_Header_Analyzer_1_0", "yara": "Yara_2_0",
                       "sandbox": None, "file_info": "FileInfo_8_0"}}
CFG = "cortex_job.cortex_utils.cortex_and_job_management._get_cortex_config"


class AbsentAiAnalyzerTests(TestCase):
    def test_the_selection_policy_still_keeps_the_eml_file_analyzers(self):
        # launch_cortex_jobs now forwards to connectors.engines.dispatch: the policy lives there.
        from connectors.base import CatalogEntry
        from connectors.engines import select_analyzers

        eml = SimpleNamespace(file_path=SimpleNamespace(name="mail.eml"))
        file_info, yara = CatalogEntry("f", "FileInfo_8_0", ()), CatalogEntry("y", "Yara_2_0", ())
        self.assertEqual(
            select_analyzers("file", eml, [file_info, yara], NO_AI["analyzers"]), [file_info]
        )

    def test_exclude_ai_analyzer_keeps_every_report(self):
        reports = [SimpleNamespace(analyzer=SimpleNamespace(name="FileInfo_8_0"))]
        with patch(CFG, return_value=NO_AI):
            self.assertEqual(CortexAnalyzerReports.exclude_ai_analyzer(reports), reports)

    def test_exclude_ai_analyzer_drops_the_default_named_report(self):
        keep = SimpleNamespace(analyzer=SimpleNamespace(name="FileInfo_8_0"))
        ai = SimpleNamespace(analyzer=SimpleNamespace(name="AI_Mail_Analyzer"))
        with patch(CFG, return_value=NO_AI):
            self.assertEqual(CortexAnalyzerReports.exclude_ai_analyzer([keep, ai]), [keep])

    def test_sync_cortex_logs_nothing_for_the_absent_role(self):
        from tasp.cron.sync_cortex import sync_cortex_analyzers

        remote = [{"id": i, "name": n} for i, n in
                  enumerate(["Mail_Header_Analyzer_1_0", "Yara_2_0", "FileInfo_8_0"])]
        with patch("tasp.cron.sync_cortex.load_config", return_value=_fake_cron_config()), \
                patch("cortex_job.cortex_utils.session_cortex_api.SessionCortexApi.do_get") as get, \
                patch("settings.config.get_section", return_value=NO_AI), \
                patch("connectors.engines.log_sync") as log:
            get.return_value.json.return_value = remote
            sync_cortex_analyzers()
        log.error.assert_not_called()
        log.warning.assert_not_called()
