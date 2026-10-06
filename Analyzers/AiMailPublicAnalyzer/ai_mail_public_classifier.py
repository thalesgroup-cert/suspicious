#!/usr/bin/env python3
"""Cortex client for AiMailPublicAnalyzer: untar, then call inference_server/.

Dispatched as the "ai_public" analyzer by launch_cortex_ai_jobs(). Its report
is comparative only and never feeds Case.results_ai. It uses standard Cortex
taxonomies, which the generic parser in score_process/scoring/cortex_analyzers/
default.py already reads.
"""
import os
import email

import requests
from cortexutils.analyzer import Analyzer

import mail_public_analysis

# Port 8091 so this server never collides with AIMailAnalyzer's 8090.
# Reachability through the bridge gateway is explained in inference_server/server.py.
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

        if not mail_public_analysis.untar_file(self.filepath, './tmp/'):
            self.error("Could not extract the submitted archive (invalid or unsafe tar)")
            return

        parts = []
        for file in sorted(os.listdir('./tmp/')):
            if file.endswith('.txt'):
                with open('./tmp/' + file, 'r') as f:
                    parts.append(f.read())
        mail_body = "\n".join(parts) if parts else None

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
