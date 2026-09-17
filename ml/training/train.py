# ml/training/train.py
#
# Trains the TRUSTVEX URL-Risk RandomForest model v1 on the prepared
# dataset produced by ml/datasets/prepare.py.
#
# Frozen hyperparameters (no grid search, no tuning):
#     n_estimators=200
#     max_depth=None
#     class_weight="balanced"
#     random_state=42
#     n_jobs=-1
#
# The point of a frozen configuration is honesty: we report one set of
# metrics produced by one model, not the best of many trials. If we
# wanted to tune later, we would use nested cross-validation with the
# same grouped-split discipline, and would document that separately.
#
# Outputs:
#     ml/models/trustvex_url_rf_v1.joblib           (the trained model)
#     ml/models/trustvex_url_rf_v1.metadata.json    (provenance + metrics)
#     ml/models/feature_names_v1.json               (the 12 feature order)
#
# No network access. No change to production code.
#
# Run (from project root, venv active):
#     python ml\training\train.py

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parent.parent  # .../ml
DATASETS_DIR = ROOT / "datasets"
DERIVED_DIR = DATASETS_DIR / "derived"
MODELS_DIR = ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

INPUT_PARQUET = DERIVED_DIR / "prepared.parquet"
MODEL_PATH = MODELS_DIR / "trustvex_url_rf_v1.joblib"
METADATA_PATH = MODELS_DIR / "trustvex_url_rf_v1.metadata.json"
FEATURE_NAMES_PATH = MODELS_DIR / "feature_names_v1.json"

# The 12 features used by the model, in the exact order the model will
# see them. This list is the contract between training and inference.
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "digit_count",
    "special_char_count",
    "has_ip_hostname",
    "has_punycode",
    "has_embedded_credentials",
    "has_unusual_port",
    "suspicious_keyword_count",
]

MODEL_VERSION = "trustvex-url-rf-v1"
SCHEMA_VERSION = "1.0"
SEED = 42


def log(msg: str) -> None:
    print(f"[train] {msg}", flush=True)


def main() -> None:
    if not INPUT_PARQUET.exists():
        log(f"missing {INPUT_PARQUET}")
        log("run ml\\datasets\\prepare.py first")
        sys.exit(2)

    log(f"loading {INPUT_PARQUET}")
    df = pd.read_parquet(INPUT_PARQUET)
    log(f"loaded {len(df):,} rows")

    # Verify the expected feature columns are present.
    missing = [f for f in FEATURE_NAMES if f not in df.columns]
    if missing:
        log(f"missing feature columns: {missing}")
        sys.exit(3)

    # Split by the 'split' column written by prepare.py.
    train = df[df["split"] == "train"].copy()
    val = df[df["split"] == "val"].copy()
    test = df[df["split"] == "test"].copy()
    log(f"train={len(train):,} val={len(val):,} test={len(test):,}")

    def to_xy(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        # Booleans -> ints. Nulls should not occur for these 12 features,
        # but if any do, fill with 0 and record the count.
        X = frame[FEATURE_NAMES].copy()
        null_counts = X.isna().sum().sum()
        if null_counts:
            log(f"WARNING: {null_counts} null values in features; filling with 0")
            X = X.fillna(0)
        X = X.astype(float).to_numpy()
        y = frame["label"].astype(int).to_numpy()
        return X, y

    X_train, y_train = to_xy(train)
    X_val, y_val = to_xy(val)
    X_test, y_test = to_xy(test)

    log("training RandomForest (frozen hyperparameters) ...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    log("training complete")

    # Evaluate on validation (informational) and test (the headline numbers).
    def metrics(y_true: np.ndarray, X: np.ndarray) -> dict:
        pred = clf.predict(X)
        prob = clf.predict_proba(X)[:, 1]
        tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()
        return {
            "n": int(len(y_true)),
            "positive_class_count": int((y_true == 1).sum()),
            "negative_class_count": int((y_true == 0).sum()),
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn),
            "precision": float(precision_score(y_true, pred, zero_division=0)),
            "recall": float(recall_score(y_true, pred, zero_division=0)),
            "f1": float(f1_score(y_true, pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_true, prob)),
        }

    val_metrics = metrics(y_val, X_val)
    test_metrics = metrics(y_test, X_test)

    log("--- validation metrics ---")
    for k, v in val_metrics.items():
        log(f"  {k}: {v}")
    log("--- test metrics (headline) ---")
    for k, v in test_metrics.items():
        log(f"  {k}: {v}")

    # Feature importances
    importances = {
        name: float(imp)
        for name, imp in sorted(
            zip(FEATURE_NAMES, clf.feature_importances_),
            key=lambda t: -t[1],
        )
    }
    log("--- feature importances ---")
    for name, imp in importances.items():
        log(f"  {name}: {imp:.4f}")

    # Save model + feature name order.
    joblib.dump(clf, MODEL_PATH)
    log(f"wrote {MODEL_PATH}")
    FEATURE_NAMES_PATH.write_text(json.dumps(FEATURE_NAMES, indent=2))
    log(f"wrote {FEATURE_NAMES_PATH}")

    # Save metadata.
    metadata = {
        "modelVersion": MODEL_VERSION,
        "featureSchemaVersion": SCHEMA_VERSION,
        "trainedAt": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sklearn.ensemble.RandomForestClassifier",
        "hyperparameters": {
            "n_estimators": 200,
            "max_depth": None,
            "class_weight": "balanced",
            "random_state": SEED,
            "n_jobs": -1,
        },
        "featureNames": FEATURE_NAMES,
        "featureCount": len(FEATURE_NAMES),
        "inputDataset": {
            "path": str(INPUT_PARQUET.relative_to(ROOT)),
            "rows": int(len(df)),
            "trainRows": int(len(train)),
            "valRows": int(len(val)),
            "testRows": int(len(test)),
        },
        "classBalance": {
            "train": {"label_0": int((y_train == 0).sum()), "label_1": int((y_train == 1).sum())},
            "val":   {"label_0": int((y_val == 0).sum()),   "label_1": int((y_val == 1).sum())},
            "test":  {"label_0": int((y_test == 0).sum()),  "label_1": int((y_test == 1).sum())},
        },
        "validationMetrics": val_metrics,
        "testMetrics": test_metrics,
        "featureImportances": importances,
        "labelProvenance": (
            "Labels are inherited from the Kaggle phishing-site-urls "
            "dataset. TRUSTVEX does NOT independently verify them."
        ),
        "knownLimitations": [
            "Model sees only 12 URL-string features. It has no visibility into TLS, DNS, redirects, page content, or reputation.",
            "Evaluation is grouped-by-registrable-domain, which tests generalization to unseen domains — NOT temporal generalization to future URLs.",
            "Tranco was not used; the benign class comes from the same Kaggle dataset as the phishing class.",
            "Hyperparameters are fixed; no tuning was performed.",
        ],
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2))
    log(f"wrote {METADATA_PATH}")
    log("done.")


if __name__ == "__main__":
    main()