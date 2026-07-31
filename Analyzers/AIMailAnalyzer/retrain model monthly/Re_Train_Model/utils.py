"""Training utilities for the monthly AIMailAnalyzer retrain pipeline."""

import json
import os
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from collections import Counter
from imblearn.over_sampling import SMOTE, RandomOverSampler
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from torch.utils.data import DataLoader, TensorDataset
from tqdm import tqdm
import hashlib

try:
    import wandb
except ImportError:  # optional - only present inside retrain-trainer:latest
    wandb = None

# ResNetMLP must be the exact architecture the production analyzer loads
# (Analyzers/AIMailAnalyzer/ResNetMLP.py), not a local copy - a prior version
# of this pipeline embedded its own ResNetMLP(input_dim, hidden_dim, output_dim)
# here, which is structurally different (no dimension narrowing, no
# residual_transform layer) and produced state_dicts that ai_mail_classifier.py
# could not load at all.
_AI_MAIL_ANALYZER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
if _AI_MAIL_ANALYZER_DIR not in sys.path:
    sys.path.insert(0, _AI_MAIL_ANALYZER_DIR)

from ResNetMLP import ResNetMLP  # noqa: E402
import mail_analysis  # noqa: E402


def num_classes_for(model_name: str) -> int:
    """Look up a model's output width from mail_analysis.MODEL_SPECS instead
    of letting each trainer redeclare its own NUM_CLASSES constant - two
    independently maintained copies of this number is exactly how health.py
    used to drift from the real dangerous_30_epochs_model shape (see the
    comment on MODEL_SPECS itself)."""
    filename = f"{model_name}.pth"
    for spec in mail_analysis.MODEL_SPECS:
        if spec.filename == filename:
            return spec.output_dim
    raise ValueError(
        f"{model_name!r} has no matching entry in mail_analysis.MODEL_SPECS "
        f"(expected filename {filename!r}) - can't infer its output width."
    )


# One file, keyed by model name, holding each past run's per-label sample
# counts - gives W&B a "previous cycle" (last month, or last 30min in the
# dev simulation) to diff the current cycle against without needing
# wandb.Api() (that needs WANDB_MODE=online + network; this sandbox defaults
# to offline, see run_monthly_cycle.sh).
_RETRAIN_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LABEL_HISTORY_PATH = os.path.join(_RETRAIN_DIR, "label_count_history.json")
_HISTORY_KEEP = 50


def load_golden_hashes() -> set:
    """golden_set.py lives one level up (retrain model monthly/, sibling of
    this Re_Train_Model/ package) - imported lazily via sys.path rather than
    a package-relative import so this module keeps working when exercised
    standalone (e.g. from the trainer Docker image's WORKDIR). Missing
    golden_set.py/golden_set.json (no golden set created yet) degrades to
    "no golden set" rather than blocking training - see golden_set.py's
    own docstring for why this evaluation is additive, not required."""
    try:
        if _RETRAIN_DIR not in sys.path:
            sys.path.insert(0, _RETRAIN_DIR)
        from golden_set import load_golden_hashes as _load_hashes
        return _load_hashes(os.path.join(_RETRAIN_DIR, "golden_set.json"))
    except Exception as exc:
        print(f"[warn] could not load golden set ({exc}) - continuing without golden-set eval")
        return set()


def _load_label_history() -> dict:
    if not os.path.exists(LABEL_HISTORY_PATH):
        return {}
    with open(LABEL_HISTORY_PATH, "r") as f:
        return json.load(f)


def _record_label_counts(model_name: str, run_timestamp: str, counts: dict):
    """Append this run's label distribution to the history file and return
    the *previous* entry for this model (None on the very first run)."""
    history = _load_label_history()
    runs = history.get(model_name, [])
    previous = runs[-1] if runs else None
    runs.append({
        "run_timestamp": run_timestamp,
        "counts": counts,
        "total": sum(counts.values()),
    })
    history[model_name] = runs[-_HISTORY_KEEP:]
    with open(LABEL_HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=2)
    return previous


def _wandb_start_run(model_name, run_timestamp, num_epochs, batch_size, num_classes, label_counts):
    """Best-effort - a broken/absent W&B setup must never fail a retrain
    cycle. Defaults to WANDB_MODE=offline (writes locally under ./wandb/,
    no account or API key needed) since this sandbox has no W&B credentials;
    set WANDB_MODE=online + WANDB_API_KEY to push to a real project instead."""
    if wandb is None or os.environ.get("WANDB_DISABLED", "").lower() == "true":
        return None

    previous = _record_label_counts(model_name, run_timestamp, label_counts)

    try:
        run = wandb.init(
            project=os.environ.get("WANDB_PROJECT", "aimailanalyzer-retrain"),
            group=run_timestamp,
            job_type="retrain",
            name=f"{model_name}-{run_timestamp}",
            mode=os.environ.get("WANDB_MODE", "offline"),
            reinit=True,
            config={
                "model_name": model_name,
                "num_epochs": num_epochs,
                "batch_size": batch_size,
                "num_classes": num_classes,
                "run_timestamp": run_timestamp,
            },
        )
    except Exception as exc:
        print(f"[wandb] init failed ({exc}) - continuing without W&B logging")
        return None

    prev_counts = previous["counts"] if previous else {}
    prev_total = previous["total"] if previous else 0
    current_total = sum(label_counts.values())

    log_payload = {f"samples/current/{label}": n for label, n in label_counts.items()}
    log_payload["samples/current/total"] = current_total

    table = wandb.Table(columns=["label", "current", "previous", "delta"])
    for label in sorted(set(label_counts) | set(prev_counts)):
        cur = label_counts.get(label, 0)
        prev = prev_counts.get(label, 0)
        table.add_data(label, cur, prev, cur - prev)
    log_payload["samples/comparison_table"] = table

    if previous:
        log_payload["samples/previous/total"] = prev_total
        log_payload["samples/delta/total"] = current_total - prev_total
        for label in set(label_counts) | set(prev_counts):
            log_payload[f"samples/previous/{label}"] = prev_counts.get(label, 0)
            log_payload[f"samples/delta/{label}"] = label_counts.get(label, 0) - prev_counts.get(label, 0)

    wandb.log(log_payload)
    return run


def calculate_hash(data, hash_type="sha256"):
    """Calculate the hash of given data."""
    if hash_type == "sha256":
        hasher = hashlib.sha256()
    elif hash_type == "md5":
        hasher = hashlib.md5()
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")

    hasher.update(data)
    return hasher.hexdigest()


def vectorize_mails(df, vectorizer):
    mask_not_vectorized = df["mpnet_vect"].isna()
    new_bodies = df.loc[mask_not_vectorized, "body"].tolist()

    if new_bodies:  # Only vectorize if there are new emails
        new_vectors = vectorizer.encode(new_bodies, show_progress_bar=True)

        if isinstance(new_vectors, np.ndarray):
            new_vectors = [vec for vec in new_vectors]

        indices_to_update = df.index[mask_not_vectorized]
        for idx, vector in zip(indices_to_update, new_vectors):
            df.at[idx, "mpnet_vect"] = vector


def smote_ros(X_train, y_train, smote_ratio=1.25, ros_ratio=1.10, random_state=42):
    """Applique SMOTE suivi de Random Over-Sampling."""
    original_counts = Counter(y_train)

    # Adapte k_neighbors si une classe a trop peu d'échantillons (cas fréquent
    # pour les sous-types "dangerous" les plus rares).
    min_samples = min(original_counts.values())
    k_neighbors = min(5, max(1, min_samples - 1))

    smote_sampling_strategy = {
        cls: int(count * smote_ratio) for cls, count in original_counts.items()
    }
    smote = SMOTE(
        sampling_strategy=smote_sampling_strategy,
        k_neighbors=k_neighbors,
        random_state=random_state,
    )
    X_smote, y_smote = smote.fit_resample(X_train, y_train)

    after_smote_count = Counter(y_smote)
    ros_sampling_strategy = {
        cls: int(count * ros_ratio) for cls, count in after_smote_count.items()
    }
    ros = RandomOverSampler(
        sampling_strategy=ros_sampling_strategy, random_state=random_state
    )
    X_resampled, y_resampled = ros.fit_resample(X_smote, y_smote)

    print("Class distribution before oversampling:", Counter(y_train))
    print("Class distribution after SMOTE:", Counter(y_smote))
    print("Class distribution after ROS:", Counter(y_resampled))

    return X_resampled, y_resampled


def pre_process(
    dataset_file,
    labels_mapping,
    y_encoder_function,
    allowed_labels,
    test_size=0.2,
    random_state=42,
    smote_ratio=1.25,
    ros_ratio=1.10,
    golden_hashes=None,
):
    """
    Pre-process the mailbox-exported dataset for training and testing.

    Args:
        dataset_file: path to dataset.pkl (or an already-loaded DataFrame),
            produced by generator_dataset.py - columns: hash, folder, body,
            mpnet_vect.
        labels_mapping: dict mapping IMAP folder name -> training label.
        y_encoder_function: encodes string labels to the int class indices
            expected by the target model (see variable.py for the ordering
            contract with mail_analysis.SubClassificationName).
        allowed_labels: labels to keep after mapping (rows with other/NaN
            labels are dropped).
        golden_hashes: set of dataset "hash" values permanently held out of
            train AND the regular random test split (see golden_set.py) -
            every cycle's model is scored against the exact same content, so
            the F1/accuracy trend means "did the model get better" instead
            of "was this cycle's random test slice easier."

    Returns:
        X_train, y_train, X_test, y_test, label_counts, X_golden, y_golden :
            numpy arrays + a {label: sample_count} dict (train+test combined,
            pre-oversampling) for the W&B "current vs previous cycle" panel.
            X_golden/y_golden are None when no golden mail for this label's
            taxonomy exists yet (e.g. brand new golden set, or a label with
            zero golden coverage).
    """
    if isinstance(dataset_file, pd.DataFrame):
        df = dataset_file.copy()
    else:
        df = pd.read_pickle(dataset_file)

    df["label"] = df["folder"].replace(labels_mapping)
    df.dropna(subset=["label"], inplace=True)

    if allowed_labels is not None:
        df = df[df["label"].isin(allowed_labels)].copy()

    label_counts = {str(k): int(v) for k, v in df["label"].value_counts().items()}

    golden_hashes = golden_hashes or set()
    df_golden = df[df["hash"].isin(golden_hashes)].copy()
    df = df[~df["hash"].isin(golden_hashes)].copy()

    df_train, df_test = train_test_split(
        df, test_size=test_size, random_state=random_state, stratify=df["label"]
    )

    X_train = np.array([np.array(x) for x in df_train["mpnet_vect"].values.tolist()])
    y_train = y_encoder_function(df_train["label"].values)

    X_resampled, y_resampled = smote_ros(
        X_train, y_train, smote_ratio=smote_ratio, ros_ratio=ros_ratio,
        random_state=random_state,
    )

    X_test = np.array([np.array(x) for x in df_test["mpnet_vect"].values.tolist()])
    y_test = y_encoder_function(df_test["label"].values)

    X_golden, y_golden = None, None
    if len(df_golden) > 0:
        X_golden = np.array([np.array(x) for x in df_golden["mpnet_vect"].values.tolist()])
        y_golden = y_encoder_function(df_golden["label"].values)

    return X_resampled, y_resampled, X_test, y_test, label_counts, X_golden, y_golden


def train_model(
    X_train,
    y_train,
    X_test,
    y_test,
    num_classes,
    model_name,
    num_epochs=30,
    batch_size=32,
    device="cpu",
    models_folder="models",
):
    """Prépare les tenseurs, entraîne le ResNetMLP de production et le sauvegarde.

    model_name must match one of mail_analysis.MODEL_SPECS filenames (without
    the .pth extension) so ai_mail_classifier.py can load it back.
    """
    X_train_tensor = torch.tensor(
        np.array([np.array(row, dtype=np.float32).flatten() for row in X_train]),
        dtype=torch.float32,
    )
    X_test_tensor = torch.tensor(
        np.array([np.array(row, dtype=np.float32).flatten() for row in X_test]),
        dtype=torch.float32,
    )
    y_train_tensor = torch.tensor(y_train, dtype=torch.long)
    y_test_tensor = torch.tensor(y_test, dtype=torch.long)

    train_loader = DataLoader(
        TensorDataset(X_train_tensor, y_train_tensor), batch_size=batch_size, shuffle=True
    )
    test_loader = DataLoader(
        TensorDataset(X_test_tensor, y_test_tensor), batch_size=batch_size, shuffle=False
    )

    input_dim = X_train_tensor.shape[1]

    # Production ResNetMLP signature: (input_dim, output_dim) - no hidden_dim,
    # the architecture narrows internally (see ResNetMLP.py).
    model = ResNetMLP(input_dim, num_classes).to(device)

    all_classes = np.arange(num_classes)
    unique_classes = np.unique(y_train)
    class_weights = compute_class_weight(
        class_weight="balanced", classes=unique_classes, y=y_train
    )
    class_weights_full = np.ones(num_classes)
    for idx, cls in enumerate(unique_classes):
        class_weights_full[cls] = class_weights[idx]
    class_weights_tensor = torch.tensor(class_weights_full, dtype=torch.float32).to(device)

    criterion = nn.CrossEntropyLoss(weight=class_weights_tensor)
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    model.train()
    training_started = time.time()
    for epoch in range(num_epochs):
        epoch_started = time.time()
        total_loss = 0
        correct = 0
        total = 0

        progress_bar = tqdm(train_loader, desc=f"Epoch {epoch+1}/{num_epochs}", leave=False)
        for X_batch, y_batch in progress_bar:
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
            progress_bar.set_postfix(loss=loss.item(), acc=100 * correct / total)

        epoch_loss = total_loss / len(train_loader)
        epoch_acc = 100 * correct / total
        print(f"Epoch {epoch+1}/{num_epochs} - Loss: {epoch_loss:.4f}, Accuracy: {epoch_acc:.2f}%")

        if wandb is not None and wandb.run is not None:
            wandb.log({
                "train/epoch": epoch + 1,
                "train/loss": epoch_loss,
                "train/accuracy": epoch_acc,
                "train/epoch_time_s": time.time() - epoch_started,
            })

    training_time_s = time.time() - training_started

    os.makedirs(models_folder, exist_ok=True)
    torch.save(model.state_dict(), os.path.join(models_folder, f"{model_name}.pth"))
    print(f"✅ {model_name}.pth saved successfully! (training time: {training_time_s:.1f}s)")

    return model, train_loader, test_loader, training_time_s


def evaluate_model(model, test_loader, target_names, device):
    """Évalue le modèle et retourne toutes les métriques (valeurs JSON-serializable)."""
    model.eval()
    y_true = []
    y_pred = []

    with torch.no_grad():
        for X_batch, y_batch in tqdm(test_loader, desc="Evaluating"):
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            outputs = model(X_batch)
            _, predicted = torch.max(outputs, 1)
            y_true.extend(y_batch.cpu().numpy())
            y_pred.extend(predicted.cpu().numpy())

    y_true = np.array(y_true)
    y_pred = np.array(y_pred)

    unique_classes = np.unique(y_true)
    if target_names is None:
        filtered_target_names = None
    else:
        filtered_target_names = [
            target_names[cls] if cls < len(target_names) else str(cls)
            for cls in unique_classes
        ]

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=unique_classes)
    report = classification_report(
        y_true, y_pred, target_names=filtered_target_names, labels=unique_classes,
        output_dict=True, zero_division=0,
    )

    print("\n" + "=" * 70)
    print("CLASSIFICATION REPORT:")
    print("=" * 70)
    print(classification_report(
        y_true, y_pred, target_names=filtered_target_names, labels=unique_classes,
        zero_division=0,
    ))
    print(f"  Accuracy  : {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  F1-Score  : {f1:.4f}")

    # Keep this JSON-serializable end to end - a previous version passed numpy
    # arrays (confusion_matrix, y_true, y_pred) straight into json.dump and
    # crashed on every run.
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "unique_classes": unique_classes.tolist(),
        "target_names": filtered_target_names,
    }


def train_model_pipeline(
    X_train, y_train, X_test, y_test, model_name, num_epochs=30,
    label_counts=None, run_timestamp=None, X_golden=None, y_golden=None,
):
    # Always derived from mail_analysis.MODEL_SPECS (single source of truth),
    # never taken from a caller-supplied value - see num_classes_for().
    num_classes = num_classes_for(model_name)

    print(f"Nombre de classes pour {model_name}: {num_classes}")

    run_timestamp = run_timestamp or datetime.now().strftime("%Y-%m-%d_%H%M%S")
    wandb_run = None
    if label_counts is not None:
        wandb_run = _wandb_start_run(
            model_name=model_name,
            run_timestamp=run_timestamp,
            num_epochs=num_epochs,
            batch_size=32,
            num_classes=num_classes,
            label_counts=label_counts,
        )

    model, train_loader, test_loader, training_time_s = train_model(
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        num_classes=num_classes,
        model_name=model_name,
        num_epochs=num_epochs,
        batch_size=32,
        device="cpu",
    )

    metrics = evaluate_model(model, test_loader, target_names=None, device="cpu")
    metrics["training_time_s"] = training_time_s
    metrics["label_counts"] = label_counts

    golden_metrics = None
    if X_golden is not None and y_golden is not None and len(X_golden) > 0:
        golden_loader = DataLoader(
            TensorDataset(
                torch.tensor(
                    np.array([np.array(row, dtype=np.float32).flatten() for row in X_golden]),
                    dtype=torch.float32,
                ),
                torch.tensor(y_golden, dtype=torch.long),
            ),
            batch_size=32, shuffle=False,
        )
        golden_metrics = evaluate_model(model, golden_loader, target_names=None, device="cpu")
        metrics["f1_score_golden"] = golden_metrics["f1_score"]
        metrics["accuracy_golden"] = golden_metrics["accuracy"]

    if wandb_run is not None:
        log_payload = {
            "eval/accuracy": metrics["accuracy"],
            "eval/precision": metrics["precision"],
            "eval/recall": metrics["recall"],
            "eval/f1_score": metrics["f1_score"],
            "train/total_time_s": training_time_s,
        }
        if golden_metrics is not None:
            log_payload["eval_golden/accuracy"] = golden_metrics["accuracy"]
            log_payload["eval_golden/f1_score"] = golden_metrics["f1_score"]
            wandb.summary["eval_golden/f1_score"] = golden_metrics["f1_score"]
        wandb.log(log_payload)
        wandb.summary["train/total_time_s"] = training_time_s
        wandb.summary["eval/f1_score"] = metrics["f1_score"]
        wandb.finish()

    return model, metrics


def save_results(model, metrics, model_name, output_dir="results"):
    """Sauvegarde les métriques (JSON) et les poids du modèle (.pth state_dict)."""
    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=4)

    torch.save(model.state_dict(), os.path.join(output_dir, f"{model_name}.pth"))


def save_dataset_info(dataset_dir, output_dir, labels=None):
    os.makedirs(output_dir, exist_ok=True)

    metadata_path = os.path.join(dataset_dir, "metadata.json")
    output_path = os.path.join(output_dir, "dataset_info.json")

    if os.path.exists(metadata_path):
        with open(metadata_path, "r") as f:
            dataset_info = json.load(f)
    else:
        print(f"[Warning] {metadata_path} n'existe pas ! Génération d'un dataset_info par défaut.")
        dataset_info = {
            "dataset_dir": dataset_dir,
            "num_classes": len(labels) if labels else None,
            "labels": labels,
            "metadata_source": "generated",
        }

    with open(output_path, "w") as f:
        json.dump(dataset_info, f, indent=4)

    print(f"Dataset info sauvegardé dans {output_path}")
