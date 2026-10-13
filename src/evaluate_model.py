"""
Model Evaluation and Metrics Inspection Module for PhishGuard
Provides functions to load saved metrics, format evaluation summaries,
and re-evaluate saved models against validation sets.
"""
import json
from pathlib import Path
from typing import Dict, Any, Optional
import config


def load_saved_metrics(metrics_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads persisted evaluation metrics from disk.
    Returns None or raises FileNotFoundError if model has not been trained yet.
    """
    if metrics_path is None:
        metrics_path = config.METRICS_PATH

    path = Path(metrics_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Metrics file not found at {path}. Please run train_model.py first."
        )

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def print_evaluation_summary(metrics: Optional[Dict[str, Any]] = None) -> None:
    """
    Prints a clean, formatted terminal summary of the evaluation metrics.
    Suitable for presentation and viva demonstrations.
    """
    if metrics is None:
        metrics = load_saved_metrics()

    stats = metrics.get("dataset_statistics", {})
    primary = metrics.get("primary_metrics", {})
    cm = primary.get("confusion_matrix", {})

    print("\n" + "=" * 60)
    print("             PHISHGUARD MODEL EVALUATION REPORT             ")
    print("=" * 60)
    print(f"Algorithm:        {metrics.get('model_type', 'N/A')}")
    print(f"Total Samples:    {stats.get('total_samples', 'N/A')}")
    print(f"Phishing Samples: {stats.get('phishing_samples', 'N/A')}")
    print(f"Legitimate Samples:{stats.get('legitimate_samples', 'N/A')}")
    print(f"Train/Test Split: {100 - int(stats.get('test_ratio', 0.2)*100)}% / {int(stats.get('test_ratio', 0.2)*100)}%")
    print(f"Dataset Nature:   {'Synthetic Demo' if stats.get('is_synthetic') else 'Real-World Import'}")
    print("-" * 60)
    print(f"Accuracy:         {primary.get('accuracy', 0.0) * 100:.2f}%")
    print(f"Precision:        {primary.get('precision', 0.0) * 100:.2f}%")
    print(f"Recall:           {primary.get('recall', 0.0) * 100:.2f}%")
    print(f"F1-Score:         {primary.get('f1_score', 0.0) * 100:.2f}%")
    print("-" * 60)
    print("Confusion Matrix:")
    print(f"  True Negatives (Legit identified as Legit):     {cm.get('true_negative', 0)}")
    print(f"  False Positives (Legit flagged as Phishing):    {cm.get('false_positive', 0)}")
    print(f"  False Negatives (Phishing missed as Legit):     {cm.get('false_negative', 0)}")
    print(f"  True Positives (Phishing correctly caught):     {cm.get('true_positive', 0)}")
    print("=" * 60)
    print("Top Predictive Features:")
    for item in metrics.get("feature_importance", [])[:5]:
        print(f"  - {item['feature']:<25}: {item['importance']:.4f}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    try:
        metrics = load_saved_metrics()
        print_evaluation_summary(metrics)
    except FileNotFoundError as e:
        print(f"[Error] {e}")
