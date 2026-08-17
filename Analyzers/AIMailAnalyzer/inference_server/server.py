#!/usr/bin/env python3
"""Persistent inference server for AIMailAnalyzer.

Loads the vectorizer and every model variant ONCE at startup and keeps them
resident in memory, instead of every Cortex job cold-loading them from disk
(the old ai_mail_classifier.py behaviour - a full SentenceTransformer +
5 ResNetMLP checkpoints, every single mail). ai_mail_classifier.py is now a
thin client: untar the mail, POST the body here, build the Cortex report
from the JSON response.

Two variants are loaded side by side - "personal" (models/, trained on this
deployment's own labeled mail) and "public" (models_public/, see that
folder's README) - so a single running server can answer for either without
a restart, letting both get dispatched as separate Cortex analyzers for the
same mail (see cortex_job/cortex_utils/cortex_and_job_management.py).

Reachability: Cortex spawns each analyzer in its own ephemeral container on
Docker's default bridge network (its docker job runner has no config to put
spawned containers on this compose stack's network - checked
/opt/cortex/conf/reference.conf, no such key exists). That network has no
DNS, so a per-job container cannot resolve this service by Compose name.
This service is instead published on the host's default-bridge gateway
(172.17.0.1 on a stock Docker install - see INFERENCE_SERVER_URL default in
ai_mail_classifier.py), which any container in the default bridge network
can always reach regardless of DNS.
"""
import os

import numpy as np
import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

import mail_analysis
from mail_analysis import MODEL_SPECS
from ResNetMLP import ResNetMLP

VECTORIZER_PATH = os.environ.get(
    "VECTORIZER_PATH",
    "/worker/AIMailAnalyzer/vectorizers/paraphrase-multilingual-mpnet-base-v2",
)
MODEL_DIRS = {
    "personal": os.environ.get("MODELS_DIR_PERSONAL", "/worker/AIMailAnalyzer/models"),
    "public": os.environ.get("MODELS_DIR_PUBLIC", "/worker/AIMailAnalyzer/models_public"),
}

SUB_LABELS = [
    "INTERNAL", "EXTERNAL", "SPAM", "NEWSLETTER",
    "CLASSIC_PHISHING", "WHALING_PHISHING", "CLONE_PHISHING", "BLACKMAILING_PHISHING",
]

device = torch.device("cpu")
app = FastAPI(title="AIMailAnalyzer inference server")

_state = {"vectorizer": None, "models": {name: {} for name in MODEL_DIRS}}


def _load_variant(variant: str, model_dir: str) -> dict:
    """Load this variant's 5 sub-models. Each is best-effort, mirroring
    ai_mail_classifier.py's own resilience: a model not yet trained for one
    variant (e.g. a fresh "public" set still missing the rarer sub-classes)
    must not block the others from loading."""
    loaded = {}
    for spec in MODEL_SPECS:
        path = os.path.join(model_dir, spec.filename)
        try:
            model = ResNetMLP(768, spec.output_dim).to(device)
            model.load_state_dict(torch.load(path, weights_only=True))
            model.eval()
            loaded[spec.filename] = model
        except Exception as exc:
            print(f"[warn] variant={variant}: could not load {spec.filename}: {exc}")
            loaded[spec.filename] = None
    return loaded


@app.on_event("startup")
def load_everything():
    print("Loading vectorizer...")
    _state["vectorizer"] = SentenceTransformer(VECTORIZER_PATH)
    for variant, model_dir in MODEL_DIRS.items():
        print(f"Loading '{variant}' models from {model_dir}...")
        _state["models"][variant] = _load_variant(variant, model_dir)
    print("Ready.")


class ClassifyRequest(BaseModel):
    mail_body: str
    variant: str = "personal"


@app.get("/health")
def health():
    return {
        "ready": _state["vectorizer"] is not None,
        "variants": {
            variant: {name: (model is not None) for name, model in models.items()}
            for variant, models in _state["models"].items()
        },
    }


@app.post("/classify")
def classify(req: ClassifyRequest):
    if req.variant not in MODEL_DIRS:
        raise HTTPException(400, f"Unknown variant {req.variant!r}, expected one of {list(MODEL_DIRS)}")
    if _state["vectorizer"] is None:
        raise HTTPException(503, "Still loading, try again shortly")

    models = _state["models"][req.variant]
    vectorizer = _state["vectorizer"]

    safe_suspicious_model = models.get("safe_suspicious_30_epochs_model.pth")
    spam_dangerous_model = models.get("spam_dangerous_30_epochs_model.pth")
    safe_model = models.get("safe_30_epochs_model.pth")
    spam_model = models.get("unwanted_30_epochs_model.pth")  # optional, see mail_analysis note
    dangerous_model = models.get("dangerous_30_epochs_model.pth")

    if not (safe_suspicious_model and spam_dangerous_model and safe_model and dangerous_model):
        raise HTTPException(503, f"Required models unavailable for variant {req.variant!r}")

    email_embedding = vectorizer.encode([req.mail_body], show_progress_bar=False)

    classification_probabilities = mail_analysis.getMainClassificationProbabilities(
        device, safe_suspicious_model, spam_dangerous_model, email_embedding
    )
    classification_info = mail_analysis.getMainClassificationInfo(classification_probabilities)

    sub_classification_probabilities = mail_analysis.getSubClassificationProbabilities(
        device, [safe_model, spam_model, dangerous_model], email_embedding, classification_probabilities
    )
    sub_classification_info = mail_analysis.getSubClassificationInfo(sub_classification_probabilities)

    classification_breakdown = mail_analysis.get_classification_breakdown(classification_probabilities)
    sub_classification_breakdown = mail_analysis.get_sub_classification_breakdown(sub_classification_probabilities)

    contributing_phrases = mail_analysis.get_contributing_phrases(
        device, safe_suspicious_model, spam_dangerous_model, vectorizer,
        req.mail_body,
        classification_index=int(np.argmax(classification_probabilities)),
        baseline_probability=float(np.max(classification_probabilities)),
    )

    main_probabilities = {
        name: f"{float(p):.2%}"
        for name, p in zip(["SAFE", "UNWANTED", "DANGEROUS"], classification_probabilities)
    }
    sub_probabilities = {
        name: f"{float(p):.2%}"
        for name, p in zip(SUB_LABELS, sub_classification_probabilities)
    }

    return {
        "malscore": str(classification_info["score"]),
        "classification": classification_info["classification"],
        "confidence": str(classification_info["confidence"]),
        "classification_probabilities": str(classification_probabilities),
        "classification_breakdown": classification_breakdown,
        "sub_classification": sub_classification_info["classification"],
        "sub_classification_confidence": str(sub_classification_info["confidence"]),
        "sub_classification_probabilities": str(sub_classification_probabilities),
        "sub_classification_breakdown": sub_classification_breakdown,
        "contributing_phrases": contributing_phrases,
        "main_probabilities": main_probabilities,
        "sub_probabilities": sub_probabilities,
        # str(list), matching the pre-refactor ai_mail_classifier.py format
        # so chromadb_utils.add_to_suspicious_collection's json.loads(...)
        # keeps working unchanged.
        "email_embedding": str(email_embedding.tolist()[0]),
    }
