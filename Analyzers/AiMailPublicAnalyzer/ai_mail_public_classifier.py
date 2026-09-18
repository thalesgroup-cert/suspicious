#!/usr/bin/env python3
"""Cortex analyzer client for AiMailPublicAnalyzer.

Thin, one-shot client (Cortex spawns this image fresh per job) - all model
loading happens in the persistent inference_server/ (see that folder's own
docstring for why). This analyzer's report is purely comparative/informative:
it is dispatched by cortex_job/cortex_utils/cortex_and_job_management.py's
launch_cortex_ai_jobs() as the "ai_public" analyzer alongside the personal
AI_Mail_Analyzer job, and is never read by Case.manage_ai_jobs / case.results_ai.

Report shape: standard Cortex taxonomy (self.build_taxonomy) rather than the
bespoke malscore/classification/confidence shape AI_Mail_Analyzer uses - the
generic Suspicious-side parser (score_process/scoring/cortex_analyzers/
default.py) already understands safe/suspicious/malicious taxonomy levels
with no analyzer-specific parser needed.
"""
import os
import email

import requests
from cortexutils.analyzer import Analyzer

import mail_public_analysis

# Same default-bridge-gateway reachability note as AIMailAnalyzer's client -
# see inference_server/server.py's docstring. Port 8091, not 8090, so this
# analyzer's persistent server never collides with AIMailAnalyzer's own.
INFERENCE_SERVER_URL = os.environ.get("AI_PUBLIC_INFERENCE_SERVER_URL", "http://172.17.0.1:8091")
INFERENCE_TIMEOUT = int(os.environ.get("INFERENCE_TIMEOUT", "60"))


class AiMailPublicClassifier(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.filename = self.getParam("attachment.name", "noname.ext")
        self.filepath = self.getParam("file", None, "File is missing")

    def summary(self, raw):
        taxonomies = []
        level = raw.get("level", "info")
        classification = raw.get("classification", "Unknown")
        confidence = raw.get("confidence")
        value = f"{classification} ({confidence:.0%})" if isinstance(confidence, (int, float)) else classification
        taxonomies.append(self.build_taxonomy(level, "AiMailPublic", "classification", value))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        mail_public_analysis.untar_file(self.filepath, './tmp/')

        mail_body = None
        for file in os.listdir('./tmp/'):
            if file.endswith('.txt'):
                with open('./tmp/' + file, 'r') as f:
                    mail_body = f.read()

        if mail_body is None:
            self.error("No mail body (.txt) found in the extracted archive")
            return

        try:
            resp = requests.post(
                f"{INFERENCE_SERVER_URL}/classify",
                json={"mail_body": mail_body},
                timeout=INFERENCE_TIMEOUT,
            )
            resp.raise_for_status()
            result = resp.json()
        except Exception as e:
            self.error(f"Error calling inference server ({INFERENCE_SERVER_URL}): {e}")
            return

        self.report({
            'classification': result['classification'],
            'confidence': result['confidence'],
            'level': result['level'],
            'classification_breakdown': result['classification_breakdown'],

            'report': {
                'mail_file_name': self.filename,
                'mail_file_path': self.filepath,
                'classification_breakdown': result['classification_breakdown'],
                'analyzed_mail_content': mail_body,
            }
        })


if __name__ == "__main__":
    AiMailPublicClassifier().run()
