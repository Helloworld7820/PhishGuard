"""
Model Training, Multi-Model Benchmarking & Artifact Persistence Pipeline for PhishGuard V2
Trains primary Random Forest model alongside Decision Tree, Logistic Regression,
and Gradient Boosting benchmarks.
Registers model artifacts and validates schemas before deployment.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

import config
from src.dataset_utils import load_and_validate_dataset
from src.feature_extraction import extract_features_vector
from src.model_registry import register_model_artifact


def extract_features_matrix(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """
    Extracts ordered feature matrix X and target vector y from dataset DataFrame.
    Guarantees that feature ordering matches config.FEATURE_NAMES strictly.
    """
    print(f"[Pipeline] Extracting features for {len(df)} URLs...")
    feature_rows = []
    for url in df["url"]:
        feature_rows.append(extract_features_vector(url))

    X = np.array(feature_rows, dtype=np.float32)
    y = df["label"].to_numpy(dtype=np.int32)
    return X, y


def train_and_evaluate(dataset_path: Path = None) -> Dict[str, Any]:
    """
    Executes end-to-end model training, multi-model comparison,
    metric calculation, and artifact persistence.
    """
    # 1. Load dataset
    df = load_and_validate_dataset(dataset_path)
    total_samples = len(df)
    phishing_count = int((df["label"] == 1).sum())
    legit_count = int((df["label"] == 0).sum())
    is_synthetic = "synthetic_demo" in df.get("dataset_type", pd.Series(["synthetic_demo"])).values
    dataset_provenance = "synthetic_demonstration_v2" if is_synthetic else "external_real_world"

    # 2. Extract features
    X, y = extract_features_matrix(df)

    # 3. Stratified Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=config.TEST_SPLIT_RATIO,
        random_state=config.RANDOM_SEED,
        stratify=y
    )

    print(f"[Pipeline] Stratified Split: Train={len(X_train)} samples, Test={len(X_test)} samples")

    # 4. Train Primary Model: Random Forest
    rf_model = RandomForestClassifier(
        n_estimators=config.MODEL_CONFIG["n_estimators"],
        max_depth=config.MODEL_CONFIG["max_depth"],
        random_state=config.MODEL_CONFIG["random_state"],
        class_weight=config.MODEL_CONFIG["class_weight"],
        n_jobs=config.MODEL_CONFIG["n_jobs"]
    )
    rf_model.fit(X_train, y_train)

    # 5. Train Baseline Comparison Models on identical split
    dt_model = DecisionTreeClassifier(
        max_depth=10,
        random_state=config.RANDOM_SEED,
        class_weight="balanced"
    )
    dt_model.fit(X_train, y_train)

    lr_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(
            max_iter=1000,
            random_state=config.RANDOM_SEED,
            class_weight="balanced"
        ))
    ])
    lr_pipeline.fit(X_train, y_train)

    hgb_model = HistGradientBoostingClassifier(
        max_iter=100,
        random_state=config.RANDOM_SEED
    )
    hgb_model.fit(X_train, y_train)

    # 6. Evaluate Primary Random Forest Model
    y_pred_rf = rf_model.predict(X_test)

    cm_rf = confusion_matrix(y_test, y_pred_rf)
    tn, fp, fn, tp = cm_rf.ravel()

    rf_metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred_rf)), 4),
        "precision": round(float(precision_score(y_test, y_pred_rf, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred_rf, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred_rf, zero_division=0)), 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
            "matrix_array": [[int(tn), int(fp)], [int(fn), int(tp)]]
        },
        "classification_report": classification_report(y_test, y_pred_rf, output_dict=True, zero_division=0)
    }

    # 7. Evaluate Baseline Models for Comparison
    y_pred_dt = dt_model.predict(X_test)
    y_pred_lr = lr_pipeline.predict(X_test)
    y_pred_hgb = hgb_model.predict(X_test)

    model_comparison = {
        "Random Forest (Selected)": {
            "accuracy": round(float(accuracy_score(y_test, y_pred_rf)), 4),
            "precision": round(float(precision_score(y_test, y_pred_rf, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred_rf, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred_rf, zero_division=0)), 4)
        },
        "Gradient Boosting (HistGB)": {
            "accuracy": round(float(accuracy_score(y_test, y_pred_hgb)), 4),
            "precision": round(float(precision_score(y_test, y_pred_hgb, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred_hgb, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred_hgb, zero_division=0)), 4)
        },
        "Decision Tree": {
            "accuracy": round(float(accuracy_score(y_test, y_pred_dt)), 4),
            "precision": round(float(precision_score(y_test, y_pred_dt, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred_dt, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred_dt, zero_division=0)), 4)
        },
        "Logistic Regression": {
            "accuracy": round(float(accuracy_score(y_test, y_pred_lr)), 4),
            "precision": round(float(precision_score(y_test, y_pred_lr, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred_lr, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred_lr, zero_division=0)), 4)
        }
    }

    # 8. Feature Importances
    importances = rf_model.feature_importances_
    feature_importance_list = [
        {"feature": name, "importance": round(float(imp), 4)}
        for name, imp in zip(config.FEATURE_NAMES, importances)
    ]
    feature_importance_list.sort(key=lambda x: x["importance"], reverse=True)

    training_timestamp = datetime.now(timezone.utc).isoformat()

    # 9. Assemble Complete Evaluation Package
    results = {
        "model_version": config.VERSION,
        "model_type": "RandomForestClassifier",
        "trained_at": training_timestamp,
        "hyperparameters": config.MODEL_CONFIG,
        "feature_names": config.FEATURE_NAMES,
        "dataset_statistics": {
            "total_samples": total_samples,
            "phishing_samples": phishing_count,
            "legitimate_samples": legit_count,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "test_ratio": config.TEST_SPLIT_RATIO,
            "is_synthetic": bool(is_synthetic),
            "dataset_provenance": dataset_provenance
        },
        "primary_metrics": rf_metrics,
        "model_comparison": model_comparison,
        "feature_importance": feature_importance_list,
        "metric_explanations": {
            "recall_note": "Recall measures the proportion of actual phishing URLs correctly caught. In cybersecurity, high recall minimizes dangerous false negatives (undetected phishing).",
            "precision_note": "Precision measures the proportion of flagged URLs that are truly phishing. High precision prevents alert fatigue and unnecessary disruption to legitimate web browsing.",
            "synthetic_disclaimer": "Metrics are computed on the designated offline test set. If synthetic demonstration data is used, scores reflect pattern discrimination capability on synthesized samples and are not representative of live in-the-wild threat environments."
        }
    }

    # 10. Persist Artifacts
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(rf_model, config.MODEL_PATH)
    joblib.dump(config.FEATURE_NAMES, config.FEATURE_NAMES_PATH)

    with open(config.METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # 11. Register in Model Registry
    register_model_artifact(
        model_path=config.MODEL_PATH,
        feature_names=config.FEATURE_NAMES,
        metrics=results,
        dataset_provenance=dataset_provenance,
        algorithm="RandomForestClassifier",
        version=config.VERSION
    )

    print(f"[Pipeline] Successfully trained and saved model to: {config.MODEL_PATH}")
    print(f"[Pipeline] Evaluation metrics saved to: {config.METRICS_PATH}")
    print(f"[Pipeline] Registered in model registry: {config.MODEL_REGISTRY_PATH}")
    print(f"[Pipeline] Accuracy: {rf_metrics['accuracy']}, Recall: {rf_metrics['recall']}, Precision: {rf_metrics['precision']}, F1: {rf_metrics['f1_score']}")

    return results


if __name__ == "__main__":
    train_and_evaluate()
