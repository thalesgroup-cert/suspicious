from enum import Enum
import numpy as np
import torch
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
    # CLASSIC_PHISHING = 4
    # SPEAR = 5
    # WHALING = 6
    # CLONE = 7
    # BLACKMAIL = 8
    # COMPROMISED = 9
    # HIJACKING = 10
    # OTHER = 11
    CLASSIC_PHISHING = 4
    CLONE = 5
    BLACKMAIL = 6
    WHALING = 7
    OTHER_PHISHING = 8

def untar_file(filepath, extract_to):
    try:
        with tarfile.open(filepath, 'r:*') as tar_ref:
            tar_ref.extractall(path=extract_to)
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
