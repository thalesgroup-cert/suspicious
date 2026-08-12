#!/usr/bin/env python3
# Author : THA-CERT //GCL

import os
import email

import requests
from cortexutils.analyzer import Analyzer

import mail_analysis

# Cortex spawns this analyzer in its own ephemeral, one-shot container per
# job (its docker job runner has no config to join spawned containers to
# this compose stack's network - checked /opt/cortex/conf/reference.conf,
# no such key). That network is Docker's default bridge, which has no DNS,
# so the persistent inference_server/ (see that folder) can't be reached by
# Compose service name here - only by the default bridge's gateway IP,
# which any container on it can always reach regardless of DNS. 172.17.0.1
# is that gateway on a stock Docker install; override via env var if a
# deployment's bridge subnet differs (`docker network inspect bridge`).
INFERENCE_SERVER_URL = os.environ.get("INFERENCE_SERVER_URL", "http://172.17.0.1:8090")
INFERENCE_TIMEOUT = int(os.environ.get("INFERENCE_TIMEOUT", "60"))


class AIMailClassifier(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        # filename of the observable
        self.filename = self.getParam("attachment.name", "noname.ext")
        self.filepath = self.getParam("file", None, "File is missing")

        # "personal" (this deployment's own trained weights) or "public"
        # (see Analyzers/AIMailAnalyzer/models_public/) - set per Cortex
        # analyzer entry in analyzers.json's config, NOT per job; two
        # separate analyzer registrations point at this same image/script
        # with different variants (see cortex_and_job_management.py's dual
        # dispatch). Purely comparative - the public variant never feeds
        # case.results_ai (see Case.manage_ai_jobs), only its own report.
        self.variant = self.getParam("config.variant", "personal")

    def summary(self, raw):
        return {
            'classification': raw.get('classification', 'Unknown'),
            'malscore': raw.get('malscore', 'Unknown'),
            'confidence': raw.get('confidence', 'Unknown')
        }

    def run(self):
        Analyzer.run(self)

        # Untar file
        mail_analysis.untar_file(self.filepath, './tmp/')

        # Get mail content and headers
        mail_body = None
        for file in os.listdir('./tmp/'):
            if file.endswith('.txt'):
                with open('./tmp/' + file, 'r') as f:
                    mail_body = f.read()
            if file.endswith('.headers'):
                with open('./tmp/' + file, 'r') as f:
                    msg = email.message_from_file(f)
                    mail_headers = mail_analysis.get_header_dict_list(msg)

        if mail_body is None:
            self.error("No mail body (.txt) found in the extracted archive")
            return

        # Classify via the persistent inference server (models loaded once
        # there, not reloaded on every job - see inference_server/server.py)
        try:
            resp = requests.post(
                f"{INFERENCE_SERVER_URL}/classify",
                json={"mail_body": mail_body, "variant": self.variant},
                timeout=INFERENCE_TIMEOUT,
            )
            resp.raise_for_status()
            result = resp.json()
        except Exception as e:
            self.error(f"Error calling inference server ({INFERENCE_SERVER_URL}, variant={self.variant}): {e}")
            return

        # Build report
        self.report({
            'malscore': result['malscore'],
            'classification': result['classification'],
            'confidence': result['confidence'],
            'classification_probabilities': result['classification_probabilities'],
            'classification_breakdown': result['classification_breakdown'],
            'sub_classification': result['sub_classification'],
            'sub_classification_confidence': result['sub_classification_confidence'],
            'sub_classification_probabilities': result['sub_classification_probabilities'],
            'sub_classification_breakdown': result['sub_classification_breakdown'],
            'contributing_phrases': result['contributing_phrases'],
            'variant': self.variant,

            'report': {
                'mail_file_name': self.filename,
                'mail_file_path': self.filepath,
                'classification_probabilities': result['classification_probabilities'],
                'main_probabilities': result['main_probabilities'],
                'sub_probabilities': result['sub_probabilities'],
                'analyzed_mail_content': mail_body,
                'variant': self.variant,
            }
        })


if __name__ == "__main__":
    AIMailClassifier().run()
