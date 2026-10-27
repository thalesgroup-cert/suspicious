#!/usr/bin/env python3
# Author : THA-CERT //GCL

import os
import email

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from cortexutils.analyzer import Analyzer

import mail_archive

# Cortex spawns this analyzer in its own ephemeral, one-shot container per
# job (its docker job runner has no config to join spawned containers to
# this compose stack's network - checked /opt/cortex/conf/reference.conf,
# no such key). That network is Docker's default bridge, which has no DNS,
# so the persistent inference_server/ (see that folder) can't be reached by
# Compose service name here - only by the default bridge's gateway IP,
# which any container on it can always reach regardless of DNS. 172.17.0.1
# is that gateway on a stock Docker install; override via the analyzer's
# `inference_url` config item or this env var if a deployment's bridge subnet
# differs (`docker network inspect bridge`).
INFERENCE_SERVER_URL = os.environ.get("INFERENCE_SERVER_URL", "http://172.17.0.1:8090")
INFERENCE_TIMEOUT = int(os.environ.get("INFERENCE_TIMEOUT", "60"))
# Attempts on connection errors / 502-504 (the server answers 503 while it is
# still loading weights after a restart). Classification is idempotent, so
# retrying a POST is safe.
INFERENCE_RETRIES = int(os.environ.get("INFERENCE_RETRIES", "3"))

# Keys the report is built from; checked up front so a server/client version
# skew surfaces as one clear error instead of a KeyError traceback.
REQUIRED_RESULT_KEYS = (
    "malscore", "classification", "confidence", "classification_probabilities",
    "classification_breakdown", "sub_classification", "sub_classification_confidence",
    "sub_classification_probabilities", "sub_classification_breakdown",
    "contributing_phrases", "main_probabilities", "sub_probabilities", "email_embedding",
)


def build_session():
    """requests session for talking to the inference server.

    trust_env is off on purpose: the target is a private bridge-gateway IP, but
    HTTP(S)_PROXY is commonly injected into containers on corporate hosts and
    `requests` would then send this call through the proxy (which can't reach
    172.17.0.1 and answers 403/502). Set INFERENCE_USE_PROXY=1 to opt back in
    for a server that really is only reachable through one.
    """
    session = requests.Session()
    session.trust_env = os.environ.get("INFERENCE_USE_PROXY", "").lower() in ("1", "true", "yes")
    retry = Retry(
        total=INFERENCE_RETRIES,
        backoff_factor=1,
        status_forcelist=(502, 503, 504),
        allowed_methods=frozenset({"POST"}),
        raise_on_status=False,
    )
    session.mount("http://", HTTPAdapter(max_retries=retry))
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def classify_remote(session, server_url, mail_body, variant, timeout=INFERENCE_TIMEOUT):
    """POST the mail body to the inference server and return its JSON result.

    Raises RuntimeError with a message that includes the server's own `detail`
    (e.g. "Required models unavailable for variant 'public'") rather than a bare
    "503 Service Unavailable".
    """
    url = f"{server_url.rstrip('/')}/classify"
    try:
        resp = session.post(url, json={"mail_body": mail_body, "variant": variant}, timeout=timeout)
    except requests.RequestException as exc:
        raise RuntimeError(f"cannot reach inference server at {url}: {exc}") from exc

    if not resp.ok:
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        raise RuntimeError(f"inference server returned HTTP {resp.status_code}: {str(detail)[:500]}")

    try:
        result = resp.json()
    except ValueError as exc:
        raise RuntimeError(f"inference server returned a non-JSON body: {resp.text[:200]!r}") from exc

    missing = [key for key in REQUIRED_RESULT_KEYS if key not in result]
    if missing:
        raise RuntimeError(f"inference server response is missing {missing} (server/client version mismatch?)")
    return result


class AIMailClassifier(Analyzer):
    def __init__(self, job_directory=None):
        Analyzer.__init__(self, job_directory)

        # filename of the observable
        self.filename = self.getParam("attachment.name", "noname.ext")
        self.filepath = self.getParam("file", None, "File is missing")

        # "personal" (this deployment's own trained weights) or "public"
        # (see Analyzers/AIMailAnalyzer/models_public/) - set per Cortex
        # analyzer entry in its configuration, NOT per job. Purely
        # comparative: the public variant must never feed case.results_ai,
        # only its own report.
        self.variant = self.getParam("config.variant", "personal")
        self.server_url = self.getParam("config.inference_url", INFERENCE_SERVER_URL)

    def summary(self, raw):
        return {
            'classification': raw.get('classification', 'Unknown'),
            'malscore': raw.get('malscore', 'Unknown'),
            'confidence': raw.get('confidence', 'Unknown')
        }

    def run(self):
        Analyzer.run(self)

        # Untar file
        if not mail_archive.untar_file(self.filepath, './tmp/'):
            self.error(f"Error extracting archive: {self.filepath}")
            return

        # Get mail content and headers
        mail_body = None
        mail_headers = None
        for file in os.listdir('./tmp/'):
            if file.endswith('.txt'):
                with open('./tmp/' + file, 'r', encoding='utf-8', errors='replace') as f:
                    mail_body = f.read()
            if file.endswith('.headers'):
                with open('./tmp/' + file, 'r', encoding='utf-8', errors='replace') as f:
                    msg = email.message_from_file(f)
                    mail_headers = mail_archive.get_header_dict_list(msg)

        if mail_body is None or mail_headers is None:
            self.error(f"Archive {self.filepath} is missing the expected .txt/.headers member")
            return

        # Classify via the persistent inference server, which owns the
        # vectorizer and every model variant (see inference_server/server.py
        # for why: this image is spawned fresh per Cortex job, so loading a
        # full SentenceTransformer + 5 ResNetMLP checkpoints here every time
        # would reload them from disk on every single mail).
        try:
            result = classify_remote(build_session(), self.server_url, mail_body, self.variant)
        except RuntimeError as e:
            self.error(f"Error calling inference server: {e}")
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

            'report': {
                'mail_file_name': self.filename,
                'mail_file_path': self.filepath,
                'classification_probabilities': result['classification_probabilities'],
                'main_probabilities': result['main_probabilities'],
                'sub_probabilities': result['sub_probabilities'],
                'analyzed_mail_content': mail_body,
                'analyzed_mail_headers': str(mail_headers),
                'email_embedding': result['email_embedding'],
            }
        })


if __name__ == "__main__":
    AIMailClassifier().run()
