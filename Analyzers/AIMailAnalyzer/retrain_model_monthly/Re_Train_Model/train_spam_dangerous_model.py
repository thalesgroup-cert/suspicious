import os
from datetime import datetime

from .utils import load_golden_hashes, pre_process, save_dataset_info, train_model_pipeline
from .variable import folders, labels_spam_dangerous, y_spam_dangerous_encoder


class Spam_Dangerous_Trainer:
    MODEL_NAME = "spam_dangerous_30_epochs_model"

    def __init__(self, dataset_dir, output_dir, run_timestamp=None):
        self.dataset_dir = dataset_dir
        self.output_dir = output_dir
        self.run_timestamp = run_timestamp or datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.model = None
        self.metrics = None

    def preprocess(self):
        dataset_file = os.path.join(self.dataset_dir, "dataset.pkl")
        return pre_process(
            dataset_file,
            labels_mapping=labels_spam_dangerous,
            y_encoder_function=y_spam_dangerous_encoder,
            allowed_labels=["spam", "dangerous"],
            golden_hashes=load_golden_hashes(),
        )

    def train(self):
        X_train, y_train, X_test, y_test, label_counts, X_golden, y_golden = self.preprocess()

        self.model, self.metrics = train_model_pipeline(
            X_train, y_train, X_test, y_test,
            model_name=self.MODEL_NAME,
            label_counts=label_counts,
            run_timestamp=self.run_timestamp,
            X_golden=X_golden,
            y_golden=y_golden,
        )

        save_dataset_info(
            dataset_dir=self.dataset_dir,
            output_dir=self.output_dir,
            labels=folders,
        )

        return self.model, self.metrics
