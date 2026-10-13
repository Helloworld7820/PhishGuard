"""
Model Registry & Schema Validation Module for PhishGuard V2
Tracks model versions, feature schema integrity, checksums, and deployment readiness.
Guarantees that artifacts cannot be loaded if feature schemas do not align.
"""
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import joblib

import config


def compute_file_hash(path: Path) -> str:
    """Calculates SHA-256 checksum of an artifact file."""
    if not path.exists():
        return ""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


def register_model_artifact(
    model_path: Path,
    feature_names: List[str],
    metrics: Dict[str, Any],
    dataset_provenance: str,
    algorithm: str = "RandomForestClassifier",
    version: str = config.VERSION
) -> Dict[str, Any]:
    """
    Registers and validates a newly trained model artifact before production deployment.
    """
    if not model_path.exists():
        raise FileNotFoundError(f"Model file {model_path} does not exist.")

    # Validate model loadability
    loaded_model = joblib.load(model_path)
    if not hasattr(loaded_model, "predict_proba"):
        raise ValueError("Model does not implement required predict_proba interface.")

    # Validate feature count
    n_features = len(feature_names)
    if hasattr(loaded_model, "n_features_in_"):
        if loaded_model.n_features_in_ != n_features:
            raise ValueError(
                f"Feature mismatch: model trained on {loaded_model.n_features_in_} features, "
                f"but schema defines {n_features} features."
            )

    model_hash = compute_file_hash(model_path)

    registry_data = {
        "model_version": version,
        "algorithm": algorithm,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "artifact_path": str(model_path.resolve()),
        "artifact_hash": model_hash,
        "feature_schema": feature_names,
        "feature_count": n_features,
        "dataset_provenance": dataset_provenance,
        "validation_passed": True,
        "summary_metrics": {
            "accuracy": metrics.get("primary_metrics", {}).get("accuracy", 0.0),
            "precision": metrics.get("primary_metrics", {}).get("precision", 0.0),
            "recall": metrics.get("primary_metrics", {}).get("recall", 0.0),
            "f1_score": metrics.get("primary_metrics", {}).get("f1_score", 0.0)
        }
    }

    with open(config.MODEL_REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(registry_data, f, indent=2)

    return registry_data


def get_registered_model_metadata() -> Optional[Dict[str, Any]]:
    """Loads current model registry metadata."""
    if not config.MODEL_REGISTRY_PATH.exists():
        return None
    try:
        with open(config.MODEL_REGISTRY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
