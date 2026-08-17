

#!/usr/bin/env python3
# Author : THA-CERT //GCL

import os
import numpy as np
import zipfile
from collections import defaultdict
import email

import requests
from cortexutils.analyzer import Analyzer
import torch
from sentence_transformers import SentenceTransformer
import time
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
        
        # Use CPU (because no gpu)
        device = torch.device("cpu")

        # Initialize vectorizer
        try:
            vectorizer = SentenceTransformer('/worker/AIMailAnalyzer/vectorizers/paraphrase-multilingual-mpnet-base-v2')
        except Exception as e:
            self.error(f"Error loading vectorizer: {e}")
            return
        
        # Load models. safe_suspicious/spam_dangerous/safe/dangerous are
        # required for the main SAFE/UNWANTED/DANGEROUS verdict. spam_model
        # (unwanted, spam-vs-newsletter) only feeds the secondary sub-
        # classification and is loaded separately - the retrain pipeline can
        # legitimately promote 4 of 5 models when one taxonomy sub-class
        # doesn't have enough labeled samples yet (see
        # main_retrainmodels.py's per-model try/except), and a missing
        # spam_model must not block reporting the main verdict.
        try:
            safe_suspicious_model = ResNetMLP(768, 2).to(device)
            safe_suspicious_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/safe_suspicious_30_epochs_model.pth", weights_only=True))
            spam_dangerous_model = ResNetMLP(768, 2).to(device)
            spam_dangerous_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/spam_dangerous_30_epochs_model.pth", weights_only=True))

            safe_model = ResNetMLP(768, 2).to(device)
            safe_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/safe_30_epochs_model.pth", weights_only=True))
            dangerous_model = ResNetMLP(768, 4).to(device)
            dangerous_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/dangerous_30_epochs_model.pth", weights_only=True))
        except Exception as e:
            self.error(f"Error loading models: {e}")
            return

        try:
            spam_model = ResNetMLP(768, 2).to(device)
            spam_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/unwanted_30_epochs_model.pth", weights_only=True))
        except Exception as e:
            print(f"[warn] unwanted_30_epochs_model.pth unavailable, sub-classification will skip spam/newsletter: {e}")
            spam_model = None

        # Untar file
        mail_analysis.untar_file(self.filepath, './tmp/')

        # Get mail content and headers
        for file in os.listdir('./tmp/'):
            if file.endswith('.txt'):
                with open('./tmp/' + file, 'r') as f:
                    mail_body = f.read()
            if file.endswith('.headers'):
                with open('./tmp/' + file, 'r') as f:
                    msg = email.message_from_file(f)
                    mail_headers = mail_analysis.get_header_dict_list(msg)
        
             
        # Get mail embedding
        email_embedding = vectorizer.encode([mail_body], show_progress_bar=False)

        # Classify mail
        classification_probabilities = mail_analysis.getMainClassificationProbabilities(device, safe_suspicious_model, spam_dangerous_model, email_embedding)
        classification_info = mail_analysis.getMainClassificationInfo(classification_probabilities)

        # Get sub classification
        sub_classification_probabilities = mail_analysis.getSubClassificationProbabilities(device, [safe_model, spam_model, dangerous_model], email_embedding, classification_probabilities)
        sub_classification_info = mail_analysis.getSubClassificationInfo(sub_classification_probabilities)

        # Explainability: labeled probability breakdowns + which sentences drove the call
        classification_breakdown = mail_analysis.get_classification_breakdown(classification_probabilities)
        sub_classification_breakdown = mail_analysis.get_sub_classification_breakdown(sub_classification_probabilities)
        contributing_phrases = mail_analysis.get_contributing_phrases(
            device, safe_suspicious_model, spam_dangerous_model, vectorizer,
            mail_body,
            classification_index=int(np.argmax(classification_probabilities)),
            baseline_probability=float(np.max(classification_probabilities)),
        )
        
# ── DEBUG : affichage façon suspicious_cli.py ──────────────────────
        SUB_LABELS = ["INTERNAL", "EXTERNAL", "SPAM", "NEWSLETTER",
                      "CLASSIC_PHISHING", "WHALING_PHISHING", "CLONE_PHISHING", "BLACKMAILING_PHISHING"]

        
        print("\nProbabilités principales :")
        for name, p in zip(["SAFE", "UNWANTED", "DANGEROUS"], classification_probabilities):
            print(f"  {name:<10} {float(p):.2%}")

        print("\nProbabilités des sous-classes :")
        for name, p in zip(SUB_LABELS, sub_classification_probabilities):
            print(f"  {name:<22} {float(p):.2%}")
        print()
   

        # ── Construction des dicts de probabilités pour le rapport Cortex ──
        main_probabilities_dict = {
            name: f"{float(p):.2%}"
            for name, p in zip(["SAFE", "UNWANTED", "DANGEROUS"], classification_probabilities)
        }
        sub_probabilities_dict = {
            name: f"{float(p):.2%}"
            for name, p in zip(SUB_LABELS, sub_classification_probabilities)
        }

        

        # Build report
        self.report({
            'malscore': str(classification_info['score']),
            'classification': classification_info['classification'],
            'confidence': str(classification_info['confidence']),
            'classification_probabilities': str(classification_probabilities),
            'classification_breakdown': classification_breakdown,
            'sub_classification': sub_classification_info['classification'],
            'sub_classification_confidence': str(sub_classification_info['confidence']),
            'sub_classification_probabilities': str(sub_classification_probabilities),
            'sub_classification_breakdown': sub_classification_breakdown,
            'contributing_phrases': contributing_phrases,
    
            'report': {
                'mail_file_name': self.filename,
                'mail_file_path': self.filepath,
                'classification_probabilities': str(classification_probabilities),
                'main_probabilities': main_probabilities_dict,
                'sub_probabilities': sub_probabilities_dict,
                'analyzed_mail_content': mail_body,
                
            }
        })
if __name__ == "__main__":
    AIMailClassifier().run()

