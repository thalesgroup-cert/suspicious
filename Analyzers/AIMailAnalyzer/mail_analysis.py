from enum import Enum
import os
from typing import NamedTuple
import numpy as np
from collections import defaultdict
import tarfile

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

# Limits for safe extraction. The archive holds an email's parsed parts
# (body .txt, .headers) — kilobytes in practice — so these caps are generous
# while still defeating a tarbomb that aims to exhaust the worker's disk.
_TAR_MAX_MEMBERS = 1_000
_TAR_MAX_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024  # 200 MB


def _is_within_directory(directory, target):
    """True if `target` resolves inside `directory` (defeats ../ traversal)."""
    abs_directory = os.path.realpath(directory)
    abs_target = os.path.realpath(target)
    prefix = os.path.join(abs_directory, "")
    return abs_target == abs_directory or abs_target.startswith(prefix)


def _safe_extract(tar_ref, extract_to):
    """Extract a tar archive defensively.

    Guards against:
      * Path traversal (CVE-2007-4559) — members with ``../`` or absolute
        paths that would write outside ``extract_to``.
      * Symlink/hardlink/device members that could redirect a later write or
        leak host files.
      * Tarbombs — too many members or too much total uncompressed data.
    """
    os.makedirs(extract_to, exist_ok=True)
    members = tar_ref.getmembers()

    if len(members) > _TAR_MAX_MEMBERS:
        raise ValueError(
            f"Archive has too many entries ({len(members)} > {_TAR_MAX_MEMBERS})."
        )

    total = 0
    for member in members:
        # Only ever extract regular files and directories. Symlinks, hardlinks,
        # FIFOs and device nodes have no business in an email-parts archive.
        if not (member.isreg() or member.isdir()):
            raise ValueError(f"Archive contains an unsupported entry type: {member.name}")

        total += max(member.size, 0)
        if total > _TAR_MAX_TOTAL_UNCOMPRESSED:
            raise ValueError("Archive uncompressed size exceeds the allowed limit.")

        target = os.path.join(extract_to, member.name)
        if not _is_within_directory(extract_to, target):
            raise ValueError(f"Archive entry escapes the extraction directory: {member.name}")

    tar_ref.extractall(path=extract_to, members=members)


def untar_file(filepath, extract_to):
    try:
        with tarfile.open(filepath, 'r:*') as tar_ref:
            _safe_extract(tar_ref, extract_to)
            print(f"File {filepath} untarred to {extract_to}")
        return True
    except Exception as e:
        print(f"Error untarring file: {e}")
        return False

def get_header_dict_list(msg):
    headers = defaultdict(list)
    for key, value in msg.items():
        headers[key].append(value)
    return headers

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

def getSubClassificationProbabilities(device, models, email_embedding, main_classification_probabilities):
    import torch
    email_tensor = torch.tensor(email_embedding, dtype=torch.float32).to(device)

    global_sub_probabilities = []

    for i, model in enumerate(models):
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
