#!/usr/bin/env python3
"""Persistent inference server for AiMailPublicAnalyzer.

Loads the vectorizer and both models once at startup instead of per Cortex
job. Separate image and process from AIMailAnalyzer's server, so neither can
break the other.

Cortex runs analyzers on Docker's default bridge, which has no DNS for Compose
service names. The port is published on the host and reached through the
bridge gateway (172.17.0.1 on a stock install); see
AI_PUBLIC_INFERENCE_SERVER_URL in ai_mail_public_classifier.py.
"""
import os
from contextlib import asynccontextmanager

import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

import mail_public_analysis
from ResNetMLP import ResNetMLP

VECTORIZER_PATH = os.environ.get(
    "VECTORIZER_PATH",
    "/worker/AiMailPublicAnalyzer/vectorizers/paraphrase-multilingual-mpnet-base-v2",
)
MODELS_DIR = os.environ.get("MODELS_DIR", "/worker/AiMailPublicAnalyzer/models")

SAFE_SUSPICIOUS_FILENAME = "safe_suspicious_model.pth"
SUSPICIOUS_DANGEROUS_FILENAME = "suspicious_dangerous_model.pth"

device = torch.device("cpu")
_state = {"vectorizer": None, "models": {}}


def _load_model(filename: str):
    path = os.path.join(MODELS_DIR, filename)
    try:
        model = ResNetMLP(768, 2).to(device)
        model.load_state_dict(torch.load(path, weights_only=True))
        model.eval()
        return model
    except Exception as exc:
        print(f"[warn] could not load {filename}: {exc}")
        return None


@asynccontextmanager
async def lifespan(_app):
    load_everything()
    yield


def load_everything():
    print("Loading vectorizer...")
    _state["vectorizer"] = SentenceTransformer(VECTORIZER_PATH)
    print(f"Loading models from {MODELS_DIR}...")
    _state["models"][SAFE_SUSPICIOUS_FILENAME] = _load_model(SAFE_SUSPICIOUS_FILENAME)
    _state["models"][SUSPICIOUS_DANGEROUS_FILENAME] = _load_model(SUSPICIOUS_DANGEROUS_FILENAME)
    print("Ready.")


app = FastAPI(title="AiMailPublicAnalyzer inference server", lifespan=lifespan)


class ClassifyRequest(BaseModel):
    mail_body: str


@app.get("/health")
def health():
    return {
        "ready": _state["vectorizer"] is not None,
        "models": {name: (model is not None) for name, model in _state["models"].items()},
    }


@app.post("/classify")
def classify(req: ClassifyRequest):
    if _state["vectorizer"] is None:
        raise HTTPException(503, "Still loading, try again shortly")

    safe_suspicious_model = _state["models"].get(SAFE_SUSPICIOUS_FILENAME)
    suspicious_dangerous_model = _state["models"].get(SUSPICIOUS_DANGEROUS_FILENAME)
    if not (safe_suspicious_model and suspicious_dangerous_model):
        raise HTTPException(503, "Required models unavailable")

    vectorizer = _state["vectorizer"]
    email_embedding = vectorizer.encode([req.mail_body], show_progress_bar=False)

    probabilities = mail_public_analysis.get_classification_probabilities(
        device, safe_suspicious_model, suspicious_dangerous_model, email_embedding
    )
    info = mail_public_analysis.get_classification_info(probabilities)
    breakdown = mail_public_analysis.get_classification_breakdown(probabilities)

    return {
        "classification": info["classification"],
        "confidence": info["confidence"],
        "level": info["level"],
        "classification_breakdown": breakdown,
    }
