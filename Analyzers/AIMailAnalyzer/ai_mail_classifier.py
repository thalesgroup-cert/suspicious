#!/usr/bin/env python3
# Author : THA-CERT //ECR

import os
import email

from cortexutils.analyzer import Analyzer
import torch
from sentence_transformers import SentenceTransformer

import mail_analysis
from ResNetMLP import ResNetMLP

class AIMailClassifier(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        
        # filename of the observable
        self.filename = self.getParam("attachment.name", "noname.ext")
        self.filepath = self.getParam("file", None, "File is missing")

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
        
        # Load models
        try:
            safe_suspicious_model = ResNetMLP(768, 2).to(device)
            safe_suspicious_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/safe_suspicious_model.pth", weights_only=True))
            spam_dangerous_model = ResNetMLP(768, 2).to(device)
            spam_dangerous_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/unwanted_dangerous_model.pth", weights_only=True))

            safe_model = ResNetMLP(768, 2).to(device)
            safe_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/safe_model.pth", weights_only=True))
            spam_model = ResNetMLP(768, 2).to(device)
            spam_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/unwanted_model.pth", weights_only=True))
            dangerous_model = ResNetMLP(768, 4).to(device)
            dangerous_model.load_state_dict(torch.load("/worker/AIMailAnalyzer/models/dangerous_model.pth", weights_only=True))
        except Exception as e:
            self.error(f"Error loading models: {e}")
            return

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

        # Build report
        self.report({
            'malscore': str(classification_info['score']),
            'classification': classification_info['classification'],
            'confidence': str(classification_info['confidence']),
            'classification_probabilities': str(classification_probabilities),
            'sub_classification': sub_classification_info['classification'],
            'sub_classification_confidence': str(sub_classification_info['confidence']),
            'sub_classification_probabilities': str(sub_classification_probabilities),
            'report': {
                'mail_file_name': self.filename,
                'mail_file_path': self.filepath,
                'classification_probabilities': str(classification_probabilities),
                'analyzed_mail_content': mail_body,
                'analyzed_mail_headers': str(mail_headers),
                'email_embedding': str(email_embedding.tolist()[0])
            }
        })

if __name__ == "__main__":
    AIMailClassifier().run()
