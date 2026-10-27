from enum import Enum
import re
from typing import NamedTuple
import numpy as np

from mail_archive import get_header_dict_list, untar_file  # noqa: F401 (re-exported)

class ClassificationName(Enum):
    SAFE = 0
    UNWANTED = 1
    DANGEROUS = 2

class SubClassificationName(Enum):
    INTERNAL = 0
    EXTERNAL = 1
    SPAM = 2
    NEWSLETTER = 3
    # ponytail: dangerous_model has 4 output neurons, so only 4 phishing
    # subtypes are reachable. Add OTHER_PHISHING back only once that model
    # is retrained with a 5th output class.
    CLASSIC_PHISHING = 4
    CLONE = 5
    BLACKMAIL = 6
    WHALING = 7


class ModelSpec(NamedTuple):
    filename: str
    output_dim: int
    group: str  # "main" (safe/suspicious vs spam/dangerous) or "sub" (phishing subtype)


# Single source of truth for every .pth file this analyzer loads, consumed by
# both ai_mail_classifier.py (real inference) and health.py (load-only probe).
# These previously drifted independently: health.py hardcoded output_dim=2
# for all five files, but dangerous_30_epochs_model.pth actually has 4 —
# load_state_dict raised a shape-mismatch there every time.
MODEL_SPECS = (
    ModelSpec("safe_suspicious_30_epochs_model.pth", 2, "main"),
    ModelSpec("spam_dangerous_30_epochs_model.pth", 2, "main"),
    ModelSpec("safe_30_epochs_model.pth", 2, "sub"),
    ModelSpec("unwanted_30_epochs_model.pth", 2, "sub"),
    ModelSpec("dangerous_30_epochs_model.pth", 4, "sub"),
)

def getMainClassificationProbabilities(device, safe_suspicious_model, spam_dangerous_model, email_embedding):
    import torch
    email_tensor = torch.tensor(email_embedding, dtype=torch.float32).to(device)

    # Get safe/suspicious probabilities
    safe_suspicious_model.eval()
    with torch.no_grad():
        output = safe_suspicious_model(email_tensor)
        probabilities_safe_suspicious = torch.softmax(output, dim=1).cpu().numpy()

    # Get spam/dangerous probabilities
    spam_dangerous_model.eval()
    with torch.no_grad():
        output = spam_dangerous_model(email_tensor)
        probabilities_spam_dangerous = torch.softmax(output, dim=1).cpu().numpy()

    global_probabilities = np.array([probabilities_safe_suspicious[0,0], probabilities_spam_dangerous[0,0]*probabilities_safe_suspicious[0,1], probabilities_spam_dangerous[0,1]*probabilities_safe_suspicious[0,1]])

    return global_probabilities

def getMainClassificationInfo(global_probabilities):
    # Get confidence
    classification_index = np.argmax(global_probabilities)
    confidence = float(global_probabilities[classification_index])

    # Get classification
    if confidence >= 0.5:
        classification = ClassificationName(classification_index).name
    else: 
        classification = "INCONCLUSIVE"
        confidence = 1 - confidence

    # Get score
    if classification == "SAFE":
        score = 5 - (confidence - 0.5) * 10  # Ranges from 0 to 5
    elif classification == "UNWANTED":
        score = 5 + (confidence - 0.5) * 3  # Ranges from 5 to 6.5
    elif classification == "DANGEROUS":
        score = 6.5 + (confidence - 0.5) * 7  # Ranges from 6.5 to 10
    else:
        score = 5  # Default fallback for unknown classification

    result = {
        'classification': classification,
        'confidence': confidence, 
        'score': round(min(max(score, 0), 10), 2)  # Ensure the score stays between 0 and 10
    }

    return result

# Output width of each sub-model, in the [safe_model, spam_model, dangerous_model]
# order getSubClassificationProbabilities is called with. Fixed by that calling
# convention (see y_dangerous_encoder in retrain_model_monthly/Re_Train_Model/
# variable.py) - not derivable from main_classification_probabilities, which
# holds one scalar weight per model position, not each model's own output width.
SUB_MODEL_WIDTHS = (2, 2, 4)


def getSubClassificationProbabilities(device, models, email_embedding, main_classification_probabilities):
    import torch
    email_tensor = torch.tensor(email_embedding, dtype=torch.float32).to(device)

    global_sub_probabilities = []

    for i, model in enumerate(models):
        if model is None:
            # Sub-model not available (e.g. not enough labeled samples yet to
            # train it). Contribute an all-zero slice so the concatenated
            # vector keeps its expected width and the downstream argmax never
            # picks a sub-class we have no signal for.
            global_sub_probabilities.append(np.zeros(SUB_MODEL_WIDTHS[i]))
            continue
        model.eval()
        with torch.no_grad():
            output = model(email_tensor)
            probabilities = torch.softmax(output, dim=1).cpu().numpy()
            
            # Multiply subclassification probabilities by main classification probability
            weighted_probabilities = probabilities[0] * main_classification_probabilities[i]

            # Append to global probabilities
            global_sub_probabilities.append(weighted_probabilities)

    return np.concatenate(global_sub_probabilities)  # Flatten the array

def getSubClassificationInfo(global_sub_probabilities):
    # Get confidence
    classification_index = np.argmax(global_sub_probabilities)
    confidence = float(global_sub_probabilities[classification_index])

    # Get classification
    if confidence >= 0.25:
        classification = SubClassificationName(classification_index).name
    else: 
        classification = "INCONCLUSIVE"
        confidence = 1 - confidence

    result = {
        'classification': classification,
        'confidence': confidence,
    }

    return result

def get_classification_breakdown(global_probabilities):
    """Label the raw main-classification array by enum name, e.g.
    {"SAFE": 0.83, "UNWANTED": 0.12, "DANGEROUS": 0.05}."""
    return {name.name: float(p) for name, p in zip(ClassificationName, global_probabilities)}

def get_sub_classification_breakdown(global_sub_probabilities):
    """Label the raw sub-classification array by enum name."""
    return {name.name: float(p) for name, p in zip(SubClassificationName, global_sub_probabilities)}

def split_into_sentences(mail_body, max_sentences=40):
    """Split a mail body into sentence-ish chunks for occlusion analysis.

    Caps at max_sentences so a pathologically long body can't turn the
    per-sentence re-embedding pass in get_contributing_phrases into an
    unbounded number of model calls.
    """
    sentences = [s.strip() for s in re.split(r'(?<=[.!?\n])\s+', mail_body) if s.strip()]
    return sentences[:max_sentences]

def rank_phrase_impacts(sentences, impacts, top_n=5):
    """Pair sentences with their occlusion impact, keep only sentences whose
    removal *reduced* confidence in the predicted class (impact > 0), and
    return the top_n by impact descending."""
    ranked = sorted(zip(sentences, impacts), key=lambda pair: pair[1], reverse=True)
    return [
        {"text": text, "impact": round(float(impact), 4)}
        for text, impact in ranked[:top_n]
        if impact > 0
    ]

def get_contributing_phrases(device, safe_suspicious_model, spam_dangerous_model, vectorizer,
                              mail_body, classification_index, baseline_probability, top_n=5):
    """Sentence-level occlusion: re-embed the body with each sentence removed
    and measure how much confidence in the predicted class drops. Sentences
    whose removal drops confidence the most are the ones driving the
    classification."""
    sentences = split_into_sentences(mail_body)
    if len(sentences) < 2:
        return []

    variants = [" ".join(sentences[:i] + sentences[i + 1:]) for i in range(len(sentences))]
    embeddings = vectorizer.encode(variants, show_progress_bar=False)

    impacts = [
        baseline_probability - getMainClassificationProbabilities(
            device, safe_suspicious_model, spam_dangerous_model, embedding.reshape(1, -1)
        )[classification_index]
        for embedding in embeddings
    ]

    return rank_phrase_impacts(sentences, impacts, top_n)
