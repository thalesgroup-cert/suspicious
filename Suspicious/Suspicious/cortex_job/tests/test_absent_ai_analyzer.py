"""integrations.cortex.analyzers.ai left the example settings with the Cortex AI analyzer; the
code that still reads it (for deployments whose Cortex catalog keeps the old analyzer) must
work when the key is absent."""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
from tasp.tests.test_sync_cortex import _fake_cron_config

NO_AI = {"analyzers": {"header": "Mail_Header_Analyzer_1_0", "yara": "Yara_2_0",
                       "sandbox": None, "file_info": "FileInfo_8_0"}}
CFG = "cortex_job.cortex_utils.cortex_and_job_management._get_cortex_config"


class AbsentAiAnalyzerTests(SimpleTestCase):
    def test_launch_cortex_jobs_still_dispatches_the_eml_file_analyzers(self):
        job = CortexJob.__new__(CortexJob)
        job.api = MagicMock()
        eml = SimpleNamespace(file_path=SimpleNamespace(name="mail.eml"))
        file_info, yara = SimpleNamespace(name="FileInfo_8_0"), SimpleNamespace(name="Yara_2_0")
        with patch(CFG, return_value=NO_AI), \
                patch.object(CortexJob, "get_file_analyzers", return_value=[file_info, yara]), \
                patch.object(CortexJob, "run", return_value=SimpleNamespace(id="r1")) as run:
            ids = job.launch_cortex_jobs(eml, "file", case=None)
        self.assertEqual(ids, ["r1"])
        self.assertEqual(run.call_args.args[1], file_info)

    def test_exclude_ai_analyzer_keeps_every_report(self):
        reports = [SimpleNamespace(analyzer=SimpleNamespace(name="FileInfo_8_0"))]
        with patch(CFG, return_value=NO_AI):
            self.assertEqual(CortexAnalyzerReports.exclude_ai_analyzer(reports), reports)

    def test_sync_cortex_logs_nothing_for_the_absent_role(self):
        from tasp.cron.sync_cortex import sync_cortex_analyzers

        remote = [{"id": i, "name": n} for i, n in
                  enumerate(["Mail_Header_Analyzer_1_0", "Yara_2_0", "FileInfo_8_0"])]
        with patch("tasp.cron.sync_cortex.load_config", return_value=_fake_cron_config()), \
                patch("cortex_job.cortex_utils.session_cortex_api.SessionCortexApi.do_get") as get, \
                patch("settings.config.get_section", return_value=NO_AI), \
                patch("tasp.cron.sync_cortex.transaction"), \
                patch("tasp.cron.sync_cortex.Analyzer"), \
                patch("tasp.cron.sync_cortex.log_analyzers") as log:
            get.return_value.json.return_value = remote
            sync_cortex_analyzers()
        log.error.assert_not_called()
        log.warning.assert_not_called()
