#!/usr/bin/env python3
"""
Day 12 - Phishing Email Detection with Machine Learning

CodingAtom Cybersecurity Internship - Phase 1

Defensive training tool that classifies SYNTHETIC email text as:
    0 = LEGIT
    1 = PHISHING

Pipeline:
    Email text
        |
        v
    TF-IDF feature extraction
        |
        v
    Multinomial Naive Bayes
        |
        v
    Prediction + confidence

Features:
    - Synthetic CSV dataset support
    - Stratified train/test split
    - TF-IDF unigram + bigram features
    - Multinomial Naive Bayes classifier
    - Accuracy / precision / recall / F1
    - Confusion matrix
    - Stratified k-fold cross-validation
    - Sample predictions with probabilities
    - JSON and text report generation
    - Reproducible results

This project does not connect to mailboxes, email services,
external targets, or live phishing infrastructure.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline


LOGGER = logging.getLogger("day12_phishing_ml")

LABEL_NAMES = {
    0: "LEGIT",
    1: "PHISHING",
}

RANDOM_STATE = 42


def configure_logging(verbose: bool = False) -> None:
    """Configure console logging."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def normalize_text(text: str) -> str:
    """Normalize whitespace without destroying useful email content."""
    return re.sub(r"\s+", " ", text).strip()


def load_dataset(dataset_path: Path) -> tuple[list[str], list[int]]:
    """
    Load and validate a CSV dataset.

    Required columns:
        text
        label

    Labels:
        0 = legitimate
        1 = phishing
    """

    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {dataset_path}"
        )

    texts: list[str] = []
    labels: list[int] = []

    with dataset_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV file has no header.")

        required_columns = {"text", "label"}
        missing = required_columns - set(reader.fieldnames)

        if missing:
            raise ValueError(
                "Missing required CSV column(s): "
                + ", ".join(sorted(missing))
            )

        for line_number, row in enumerate(reader, start=2):
            text = normalize_text(row.get("text", ""))
            raw_label = str(row.get("label", "")).strip()

            if not text:
                raise ValueError(
                    f"Empty email text at CSV line {line_number}."
                )

            if raw_label not in {"0", "1"}:
                raise ValueError(
                    f"Invalid label at CSV line {line_number}: "
                    f"{raw_label!r}. Expected 0 or 1."
                )

            texts.append(text)
            labels.append(int(raw_label))

    if len(texts) < 20:
        raise ValueError(
            "Dataset contains fewer than 20 samples. "
            "Use a larger synthetic dataset."
        )

    if set(labels) != {0, 1}:
        raise ValueError(
            "Dataset must contain both legitimate (0) "
            "and phishing (1) samples."
        )

    return texts, labels


def build_model() -> Pipeline:
    """
    Build the complete ML pipeline.

    TF-IDF converts text into numerical features.
    MultinomialNB performs the classification.
    """

    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                    max_features=5000,
                ),
            ),
            (
                "classifier",
                MultinomialNB(alpha=0.5),
            ),
        ]
    )


def evaluate_model(
    model: Pipeline,
    x_test: list[str],
    y_test: list[int],
) -> dict:
    """Evaluate the model against previously unseen test data."""

    predictions = model.predict(x_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test,
        predictions,
        average="binary",
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1],
    )

    report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["LEGIT", "PHISHING"],
        zero_division=0,
    )

    return {
        "accuracy": round(float(accuracy), 4),
        "precision_phishing": round(float(precision), 4),
        "recall_phishing": round(float(recall), 4),
        "f1_phishing": round(float(f1), 4),
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
    }


def cross_validate(
    texts: list[str],
    labels: list[int],
    folds: int = 5,
) -> dict:
    """
    Perform stratified k-fold cross-validation.

    A fresh pipeline is created so every fold performs its own
    feature fitting without leaking test-fold information.
    """

    model = build_model()

    splitter = StratifiedKFold(
        n_splits=folds,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    scores = cross_val_score(
        model,
        texts,
        labels,
        cv=splitter,
        scoring="f1",
    )

    return {
        "folds": folds,
        "f1_scores": [
            round(float(score), 4)
            for score in scores
        ],
        "mean_f1": round(
            float(scores.mean()),
            4,
        ),
        "std_f1": round(
            float(scores.std()),
            4,
        ),
    }


def predict_samples(
    model: Pipeline,
    samples: list[str],
) -> list[dict]:
    """Generate predictions and class probabilities."""

    cleaned_samples = [
        normalize_text(sample)
        for sample in samples
    ]

    predictions = model.predict(cleaned_samples)
    probabilities = model.predict_proba(cleaned_samples)

    results = []

    for text, prediction, probability in zip(
        cleaned_samples,
        predictions,
        probabilities,
    ):
        predicted_label = int(prediction)

        results.append(
            {
                "text": text,
                "prediction": LABEL_NAMES[predicted_label],
                "label": predicted_label,
                "confidence": round(
                    float(probability[predicted_label]),
                    4,
                ),
                "phishing_probability": round(
                    float(probability[1]),
                    4,
                ),
                "legitimate_probability": round(
                    float(probability[0]),
                    4,
                ),
            }
        )

    return results


def save_json(
    path: Path,
    data: dict,
) -> None:
    """Save a JSON artifact."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )


def save_text_report(
    path: Path,
    metrics: dict,
    cv_metrics: dict,
) -> None:
    """Save a human-readable classification report."""

    matrix = metrics["confusion_matrix"]

    content = f"""
DAY 12 — PHISHING EMAIL ML CLASSIFIER
=====================================

MODEL
-----
TF-IDF Vectorization + Multinomial Naive Bayes


HELD-OUT TEST RESULTS
---------------------
Accuracy:             {metrics["accuracy"]:.2%}
Precision (Phishing): {metrics["precision_phishing"]:.2%}
Recall (Phishing):    {metrics["recall_phishing"]:.2%}
F1 (Phishing):        {metrics["f1_phishing"]:.2%}


CONFUSION MATRIX
----------------
Rows    = Actual
Columns = Predicted

             LEGIT    PHISHING
LEGIT        {matrix[0][0]:5d}    {matrix[0][1]:5d}
PHISHING     {matrix[1][0]:5d}    {matrix[1][1]:5d}


CLASSIFICATION REPORT
---------------------
{metrics["classification_report"]}


STRATIFIED CROSS-VALIDATION
---------------------------
Folds:     {cv_metrics["folds"]}
F1 scores: {cv_metrics["f1_scores"]}
Mean F1:   {cv_metrics["mean_f1"]:.2%}
Std F1:    {cv_metrics["std_f1"]:.2%}


IMPORTANT LIMITATION
--------------------
This project uses a synthetic and relatively small dataset.

The measured metrics demonstrate the ML workflow and should not be
interpreted as real-world phishing detection performance.

A production detector would require:
- Much larger datasets
- Diverse phishing campaigns
- Legitimate mail from many organizations
- Temporal validation
- Continuous retraining
- URL/domain analysis
- Sender authentication signals
- Attachment analysis
- Human review for uncertain cases
"""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content.strip() + "\n",
        encoding="utf-8",
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Day 12 defensive phishing-email "
            "classification tool."
        )
    )

    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("input/emails.csv"),
        help="Path to CSV dataset.",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory for generated reports.",
    )

    parser.add_argument(
        "--test-size",
        type=float,
        default=0.25,
        help="Test-set fraction. Default: 0.25",
    )

    parser.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        help="Number of cross-validation folds. Default: 5",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    return parser.parse_args()


def main() -> int:
    """Application entry point."""

    args = parse_arguments()

    configure_logging(
        verbose=args.verbose
    )

    if not 0.10 <= args.test_size <= 0.40:
        LOGGER.error(
            "Test size must be between 0.10 and 0.40."
        )
        return 2

    if args.cv_folds < 3:
        LOGGER.error(
            "Cross-validation requires at least 3 folds."
        )
        return 2

    try:
        texts, labels = load_dataset(
            args.dataset
        )

        legitimate_count = labels.count(0)
        phishing_count = labels.count(1)

        LOGGER.info(
            "Loaded %d synthetic emails.",
            len(texts),
        )

        LOGGER.info(
            "Legitimate: %d | Phishing: %d",
            legitimate_count,
            phishing_count,
        )

        # -----------------------------------------
        # Train / test split
        # -----------------------------------------

        (
            x_train,
            x_test,
            y_train,
            y_test,
        ) = train_test_split(
            texts,
            labels,
            test_size=args.test_size,
            random_state=RANDOM_STATE,
            stratify=labels,
        )

        LOGGER.info(
            "Training samples: %d",
            len(x_train),
        )

        LOGGER.info(
            "Testing samples: %d",
            len(x_test),
        )

        # -----------------------------------------
        # Train model
        # -----------------------------------------

        model = build_model()

        LOGGER.info(
            "Training TF-IDF + MultinomialNB model..."
        )

        model.fit(
            x_train,
            y_train,
        )

        # -----------------------------------------
        # Evaluate
        # -----------------------------------------

        metrics = evaluate_model(
            model,
            x_test,
            y_test,
        )

        # -----------------------------------------
        # Cross-validation
        # -----------------------------------------

        LOGGER.info(
            "Running %d-fold stratified cross-validation...",
            args.cv_folds,
        )

        cv_metrics = cross_validate(
            texts,
            labels,
            folds=args.cv_folds,
        )

        # -----------------------------------------
        # Refit using complete dataset
        # -----------------------------------------

        model.fit(
            texts,
            labels,
        )

        # -----------------------------------------
        # Demonstration predictions
        # -----------------------------------------

        demo_samples = [
            (
                "Urgent security alert: verify your PayPal "
                "password immediately using the secure link."
            ),
            (
                "Hi team, the project meeting is confirmed "
                "for Tuesday at 3 PM. The agenda is attached."
            ),
            (
                "Your bank account will be suspended today "
                "unless you confirm your payment details."
            ),
            (
                "Please review the quarterly budget document "
                "before tomorrow's planning meeting."
            ),
        ]

        predictions = predict_samples(
            model,
            demo_samples,
        )

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        # -----------------------------------------
        # JSON artifacts
        # -----------------------------------------

        model_results = {
            "metadata": {
                "generated_utc": timestamp,
                "dataset": str(args.dataset),
                "dataset_size": len(texts),
                "legitimate_count": legitimate_count,
                "phishing_count": phishing_count,
                "test_size": args.test_size,
                "random_state": RANDOM_STATE,
                "model": (
                    "TfidfVectorizer + MultinomialNB"
                ),
            },
            "held_out_test": metrics,
            "cross_validation": cv_metrics,
        }

        prediction_results = {
            "generated_utc": timestamp,
            "model": (
                "TfidfVectorizer + MultinomialNB"
            ),
            "predictions": predictions,
        }

        save_json(
            args.output_dir / "model_results.json",
            model_results,
        )

        save_json(
            args.output_dir / "predictions.json",
            prediction_results,
        )

        save_text_report(
            args.output_dir / "classification_report.txt",
            metrics,
            cv_metrics,
        )

        # -----------------------------------------
        # Console summary
        # -----------------------------------------

        print()
        print("=" * 72)
        print("🎣 DAY 12 — PHISHING EMAIL ML CLASSIFIER")
        print("=" * 72)

        print(
            f"Dataset       : {len(texts)} synthetic emails"
        )

        print(
            f"Test accuracy : {metrics['accuracy']:.2%}"
        )

        print(
            f"Phishing F1   : {metrics['f1_phishing']:.2%}"
        )

        print(
            f"CV mean F1    : {cv_metrics['mean_f1']:.2%}"
        )

        print()
        print("Sample predictions:")
        print("-" * 72)

        for index, result in enumerate(
            predictions,
            start=1,
        ):
            print(
                f"[{index}] "
                f"{result['prediction']:<9} "
                f"confidence="
                f"{result['confidence']:.2%} | "
                f"{result['text']}"
            )

        print()
        print("-" * 72)

        print(
            "[+] JSON metrics : "
            f"{args.output_dir / 'model_results.json'}"
        )

        print(
            "[+] Predictions  : "
            f"{args.output_dir / 'predictions.json'}"
        )

        print(
            "[+] Text report  : "
            f"{args.output_dir / 'classification_report.txt'}"
        )

        print("=" * 72)

        LOGGER.info(
            "Analysis completed successfully."
        )

        return 0

    except (
        FileNotFoundError,
        ValueError,
    ) as exc:

        LOGGER.error(
            "%s",
            exc,
        )

        return 1

    except Exception:

        LOGGER.exception(
            "Unexpected classifier error."
        )

        return 1


if __name__ == "__main__":
    sys.exit(main())
