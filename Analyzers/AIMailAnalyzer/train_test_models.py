#!/usr/bin/env python3
"""Headless, scripted equivalent of train_models.ipynb, for a test deployment
with no interactive Jupyter session. Same algorithm, same hyperparameters,
same 5-model pipeline as the notebook -- transcribed to a plain script so it
can run inside a container via `python train_test_models.py`. Saves models
under the exact filenames mail_analysis.MODEL_SPECS / ai_mail_classifier.py
expect (the notebook itself saves under different names -- see AIMailAnalyzer
README/PR notes) so the analyzer can load them without renaming.

Usage:
    python train_test_models.py --csv mailbox_dataset.csv --out models
"""
import argparse
import hashlib
import re
import sys
from collections import Counter

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from imblearn.over_sampling import RandomOverSampler, SMOTE
from imblearn.pipeline import Pipeline
from imblearn.under_sampling import RandomUnderSampler
from sentence_transformers import SentenceTransformer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from torch.utils.data import DataLoader, TensorDataset
from tqdm import tqdm

from mail_analysis import SubClassificationName
from ResNetMLP import ResNetMLP

# y_encoder order must match SubClassificationName exactly for indices >= 4 --
# the dangerous_model's output neurons are positional, not name-keyed.
Y_ENCODER = {
    "LEGIT_INTERNAL_COMMUNICATION": 0,
    "LEGIT_EXTERNAL_COMMUNICATION": 1,
    "SPAM": 2,
    "NEWSLETTER": 3,
    "CLASSIC_PHISHING": 4,
    "CLONE_PHISHING": 5,
    "BLACKMAILING_PHISHING": 6,
    "WHALING_PHISHING": 7,
}
assert [Y_ENCODER[k] for k in ("CLASSIC_PHISHING", "CLONE_PHISHING", "BLACKMAILING_PHISHING", "WHALING_PHISHING")] == [
    m.value for m in (SubClassificationName.CLASSIC_PHISHING, SubClassificationName.CLONE,
                       SubClassificationName.BLACKMAIL, SubClassificationName.WHALING)
]

# Target filenames the analyzer/health-probe actually load (mail_analysis.MODEL_SPECS),
# not the names train_models.ipynb happens to save under.
FILENAME_BY_ROLE = {
    "safe_suspicious": "safe_suspicious_30_epochs_model.pth",
    "spam_dangerous": "spam_dangerous_30_epochs_model.pth",
    "safe": "safe_30_epochs_model.pth",
    "unwanted": "unwanted_30_epochs_model.pth",
    "dangerous": "dangerous_30_epochs_model.pth",
}

TEST_SIZE = 0.2
RANDOM_STATE = 42
SMOTE_FACTOR = 1.2
ROS_FACTOR = 1.1
CAP_MULT = 1.75
BATCH_SIZE = 8
LEARNING_RATE = 0.005
EPOCHS = 15


def process_body(text: str) -> str:
    patterns = [
        (r" |\r", ""),
        (r" +\n", "\n"),
        (r"=\n", ""),
        (r"\[cid:.*?\]\n?", ""),
        (r"Sensitivity:.*\n", ""),
        (r"Critère de diffusion ?:.*\n", ""),
        (r"\n{3,}", "\n\n"),
        (r"((From|De).*)\n\n", r"\1\n"),
        (r"^\s+|\s+$", ""),
    ]
    for pat, repl in patterns:
        text = re.sub(pat, repl, text, flags=re.MULTILINE)
    return text


def calculate_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def remove_similar_mails(df: pd.DataFrame, field: str, threshold: float = 0.9) -> pd.DataFrame:
    from sklearn.metrics.pairwise import cosine_similarity
    vectors = np.vstack(df[field].values)
    similarity_matrix = cosine_similarity(vectors)
    to_remove = set()
    n = len(df)
    for i in tqdm(range(n), desc="Removing similar mails"):
        if i in to_remove:
            continue
        for j in range(i + 1, n):
            if j in to_remove:
                continue
            if similarity_matrix[i, j] > threshold:
                to_remove.add(j)
    keep = [i for i in range(n) if i not in to_remove]
    return df.iloc[keep].reset_index(drop=True)


def oversample_data(X_train, y_train, smote_factor=SMOTE_FACTOR, ros_factor=ROS_FACTOR,
                     random_state=RANDOM_STATE, cap_mult=CAP_MULT):
    original_counts = Counter(y_train)
    mean_n = int(pd.Series(list(original_counts.values())).mean())
    undersample_cap = int(cap_mult * mean_n)

    ros_strategy = {}
    for cls, n in original_counts.items():
        if n < mean_n:
            target = min(int(n * ros_factor), mean_n)
            if target > n:
                ros_strategy[cls] = target
    steps = []
    if ros_strategy:
        steps.append(("ros", RandomOverSampler(sampling_strategy=ros_strategy, random_state=random_state)))

    if steps:
        X_tmp, y_tmp = Pipeline(steps).fit_resample(X_train, y_train)
        after_ros = Counter(y_tmp)
    else:
        after_ros = original_counts

    smote_strategy = {}
    for cls, n in after_ros.items():
        if n < mean_n:
            target = min(int(n * smote_factor), mean_n)
            if target > n:
                smote_strategy[cls] = target
    if smote_strategy:
        min_class_n = min(smote_strategy.values())
        k = max(2, min(5, min_class_n - 1))
        steps.append(("smote", SMOTE(sampling_strategy=smote_strategy, random_state=random_state, k_neighbors=k)))

    after_smote_preview = Counter(Pipeline(steps).fit_resample(X_train, y_train)[1]) if steps else original_counts
    rus_strategy = {cls: undersample_cap for cls, n in after_smote_preview.items() if n > undersample_cap}
    if rus_strategy:
        steps.append(("rus", RandomUnderSampler(sampling_strategy=rus_strategy, random_state=random_state)))

    if not steps:
        return X_train, y_train

    X_res, y_res = Pipeline(steps).fit_resample(X_train, y_train)
    print(f"  mean={mean_n} undersample_cap={undersample_cap} before={original_counts} after={Counter(y_res)}")
    return X_res, y_res


def train_model(model, loader, num_epochs, model_name, criterion, optimizer, device, out_path):
    model.train()
    for epoch in range(num_epochs):
        total_loss, correct, total = 0.0, 0, 0
        for X_batch, y_batch in loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            _, predicted = torch.max(outputs, 1)
            correct += (predicted == y_batch).sum().item()
            total += y_batch.size(0)
        print(f"    [{model_name}] epoch {epoch+1}/{num_epochs} loss={total_loss/len(loader):.4f} acc={100*correct/total:.2f}%")
    torch.save(model.state_dict(), out_path)
    print(f"  saved {out_path}")


def evaluate_model(model, loader, target_names, device):
    model.eval()
    y_true, y_pred = [], []
    with torch.no_grad():
        for X_batch, y_batch in loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            outputs = model(X_batch)
            _, predicted = torch.max(outputs, 1)
            y_true.extend(y_batch.cpu().numpy())
            y_pred.extend(predicted.cpu().numpy())
    print(classification_report(y_true, y_pred, target_names=target_names, zero_division=0))


def _tensor(X):
    return torch.tensor(np.array([np.array(row).flatten() for row in X]), dtype=torch.float32)


def _train_one(role, X_train, y_train, X_test, y_test, target_names, device, out_dir):
    print(f"\n=== {role} ===")
    Xtr, ytr = _tensor(X_train), torch.tensor(y_train, dtype=torch.long)
    Xte, yte = _tensor(X_test), torch.tensor(y_test, dtype=torch.long)
    train_loader = DataLoader(TensorDataset(Xtr, ytr), batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(TensorDataset(Xte, yte), batch_size=BATCH_SIZE, shuffle=False)

    input_dim = Xtr.shape[1]
    output_dim = len(np.unique(ytr.numpy()))
    class_weights = compute_class_weight(class_weight="balanced", classes=np.unique(ytr.numpy()), y=ytr.numpy())
    class_weights_tensor = torch.tensor(class_weights, dtype=torch.float32).to(device)

    model = ResNetMLP(input_dim, output_dim).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights_tensor)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)

    out_path = f"{out_dir}/{FILENAME_BY_ROLE[role]}"
    train_model(model, train_loader, EPOCHS, role, criterion, optimizer, device, out_path)
    evaluate_model(model, test_loader, target_names, device)
    return model


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out", default="models")
    ap.add_argument("--vectorizer", default="vectorizers/paraphrase-multilingual-mpnet-base-v2")
    args = ap.parse_args()

    import os
    os.makedirs(args.out, exist_ok=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"device: {device}")

    df = pd.read_csv(args.csv)
    missing = {"body", "label"} - set(df.columns)
    if missing:
        sys.exit(f"CSV missing column(s): {missing}")
    unknown = set(df["label"].unique()) - set(Y_ENCODER.keys())
    if unknown:
        sys.exit(f"CSV has label(s) not in Y_ENCODER: {unknown}")

    df = df.dropna(subset=["body", "label"])
    df["body"] = df["body"].apply(process_body)
    df["hash"] = df["body"].apply(lambda x: calculate_hash(x.encode("utf-8")))
    df = df.drop_duplicates(subset=["body", "label"]).dropna()

    print(f"Loaded {len(df)} rows:")
    print(df["label"].value_counts())

    print("\nVectorizing...")
    vectorizer = SentenceTransformer(args.vectorizer, device=str(device))
    df["vect"] = [vectorizer.encode(b, convert_to_numpy=True) for b in tqdm(df["body"], desc="Encoding")]

    df = remove_similar_mails(df, "vect", threshold=0.9)
    print(f"\nAfter near-duplicate removal: {len(df)} rows")
    print(df["label"].value_counts())

    df_train, df_test = train_test_split(df, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=df["label"])
    X_train = np.vstack(df_train["vect"].values)
    X_test = np.vstack(df_test["vect"].values)
    y_train = df_train["label"].map(Y_ENCODER).values
    y_test = df_test["label"].map(Y_ENCODER).values

    print("\nOversampling...")
    X_train, y_train = oversample_data(X_train, y_train)

    # --- safe_suspicious: 0/1 -> safe(0) vs suspicious(1) ---
    y_train_ss = np.array([0 if v < 2 else 1 for v in y_train])
    y_test_ss = np.array([0 if v < 2 else 1 for v in y_test])
    _train_one("safe_suspicious", X_train, y_train_ss, X_test, y_test_ss, ["safe", "suspicious"], device, args.out)

    # --- spam_dangerous (a.k.a. unwanted/dangerous): on classes [2..7] -> unwanted(0)/dangerous(1) ---
    mask_tr = np.isin(y_train, [2, 3, 4, 5, 6, 7])
    mask_te = np.isin(y_test, [2, 3, 4, 5, 6, 7])
    y_train_ud = np.array([0 if v < 4 else 1 for v in y_train[mask_tr]])
    y_test_ud = np.array([0 if v < 4 else 1 for v in y_test[mask_te]])
    _train_one("spam_dangerous", X_train[mask_tr], y_train_ud, X_test[mask_te], y_test_ud,
               ["unwanted", "dangerous"], device, args.out)

    # --- safe: on classes [0,1] -> internal(0)/external(1) ---
    mask_tr = np.isin(y_train, [0, 1])
    mask_te = np.isin(y_test, [0, 1])
    _train_one("safe", X_train[mask_tr], y_train[mask_tr], X_test[mask_te], y_test[mask_te],
               ["internal", "external"], device, args.out)

    # --- unwanted: on classes [2,3] -> spam(0)/newsletter(1) ---
    mask_tr = np.isin(y_train, [2, 3])
    mask_te = np.isin(y_test, [2, 3])
    y_train_u = np.array([0 if v == 2 else 1 for v in y_train[mask_tr]])
    y_test_u = np.array([0 if v == 2 else 1 for v in y_test[mask_te]])
    _train_one("unwanted", X_train[mask_tr], y_train_u, X_test[mask_te], y_test_u,
               ["spam", "newsletter"], device, args.out)

    # --- dangerous: on classes [4,5,6,7] -> classic(0)/clone(1)/blackmail(2)/whaling(3) ---
    mask_tr = np.isin(y_train, [4, 5, 6, 7])
    mask_te = np.isin(y_test, [4, 5, 6, 7])
    y_train_d = np.array([v - 4 for v in y_train[mask_tr]])
    y_test_d = np.array([v - 4 for v in y_test[mask_te]])
    _train_one("dangerous", X_train[mask_tr], y_train_d, X_test[mask_te], y_test_d,
               ["classic", "clone", "blackmail", "whaling"], device, args.out)

    print("\nAll 5 models trained and saved to", args.out)


if __name__ == "__main__":
    main()
