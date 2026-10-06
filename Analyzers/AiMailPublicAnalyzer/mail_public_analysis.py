import os
import tarfile
from enum import Enum
from collections import defaultdict

# Copied from AIMailAnalyzer/mail_analysis.py (CVE-2007-4559, tarbombs) rather
# than imported: this image only COPYs its own directory.

_TAR_MAX_MEMBERS = 1_000
_TAR_MAX_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024  # 200 MB


def _is_within_directory(directory, target):
    abs_directory = os.path.realpath(directory)
    abs_target = os.path.realpath(target)
    prefix = os.path.join(abs_directory, "")
    return abs_target == abs_directory or abs_target.startswith(prefix)


def _safe_extract(tar_ref, extract_to):
    os.makedirs(extract_to, exist_ok=True)
    members = tar_ref.getmembers()

    if len(members) > _TAR_MAX_MEMBERS:
        raise ValueError(
            f"Archive has too many entries ({len(members)} > {_TAR_MAX_MEMBERS})."
        )

    total = 0
    for member in members:
        if not (member.isreg() or member.isdir()):
            raise ValueError(f"Archive contains an unsupported entry type: {member.name}")

        total += max(member.size, 0)
        if total > _TAR_MAX_TOTAL_UNCOMPRESSED:
            raise ValueError("Archive uncompressed size exceeds the allowed limit.")

        target = os.path.join(extract_to, member.name)
        if not _is_within_directory(extract_to, target):
            raise ValueError(f"Archive entry escapes the extraction directory: {member.name}")

    tar_ref.extractall(path=extract_to, members=members, filter="data")


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


# Cascade as in AIMailAnalyzer's getMainClassificationProbabilities: the second
# model is weighted by the first one's "not safe" probability, so DANGEROUS
# needs both models to agree.

class ClassificationName(Enum):
    SAFE = 0
    SUSPICIOUS = 1
    DANGEROUS = 2


def get_classification_probabilities(device, safe_suspicious_model, suspicious_dangerous_model, email_embedding):
    import torch

    email_tensor = torch.tensor(email_embedding, dtype=torch.float32).to(device)

    safe_suspicious_model.eval()
    with torch.no_grad():
        output = safe_suspicious_model(email_tensor)
        p1 = torch.softmax(output, dim=1).cpu().numpy()  # [P(safe), P(suspicious)]

    suspicious_dangerous_model.eval()
    with torch.no_grad():
        output = suspicious_dangerous_model(email_tensor)
        p2 = torch.softmax(output, dim=1).cpu().numpy()  # [P(suspicious), P(dangerous)]

    import numpy as np
    global_probabilities = np.array([
        p1[0, 0],               # SAFE
        p1[0, 1] * p2[0, 0],    # SUSPICIOUS
        p1[0, 1] * p2[0, 1],    # DANGEROUS
    ])
    return global_probabilities


def get_classification_info(global_probabilities):
    import numpy as np

    classification_index = int(np.argmax(global_probabilities))
    confidence = float(global_probabilities[classification_index])

    if confidence >= 0.5:
        classification = ClassificationName(classification_index).name
    else:
        classification = "INCONCLUSIVE"
        confidence = 1 - confidence

    # "malicious" is Cortex's word for the worst band (SEVERITY_ORDER in
    # score_process/scoring/cortex_analyzers/default.py).
    level_by_classification = {
        "SAFE": "safe",
        "SUSPICIOUS": "suspicious",
        "DANGEROUS": "malicious",
        "INCONCLUSIVE": "info",
    }

    return {
        "classification": classification,
        "confidence": confidence,
        "level": level_by_classification[classification],
    }


def get_classification_breakdown(global_probabilities):
    """Label the raw classification array by enum name, e.g.
    {"SAFE": 0.83, "SUSPICIOUS": 0.12, "DANGEROUS": 0.05}."""
    return {
        name.name: float(global_probabilities[name.value])
        for name in ClassificationName
    }
