# ml/service/predictor.py
#
# Loads the trained TRUSTVEX URL-Risk RandomForest model and produces
# predictions from the 12 URL-string features.
#
# The model is expected at ml/models/trustvex_url_rf_v1.joblib, alongside
# ml/models/trustvex_url_rf_v1.metadata.json and feature_names_v1.json.
#
# If the model file is missing or fails to load, the service reports an
# "unavailable" status rather than pretending to predict. See main.py for
# how that's surfaced to the caller.

import json
from pathlib import Path
from typing import List, Optional

import joblib
import numpy as np

# Model directory: ml/models/, sibling to ml/service/.
_SERVICE_DIR = Path(__file__).resolve().parent
_MODELS_DIR = _SERVICE_DIR.parent / "models"

_MODEL_PATH = _MODELS_DIR / "trustvex_url_rf_v1.joblib"
_METADATA_PATH = _MODELS_DIR / "trustvex_url_rf_v1.metadata.json"
_FEATURE_NAMES_PATH = _MODELS_DIR / "feature_names_v1.json"

# The trained model was produced by ml/training/train.py using a fixed
# feature order. The service must load and use the same order at
# inference time, otherwise feature values will be assigned to the wrong
# model inputs.
DEFAULT_FEATURE_NAMES: List[str] = [
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


class Predictor:
    """
    Wraps the trained model. Loads the artifact once at construction.
    If loading fails, `available` is False and every call to predict()
    raises RuntimeError — callers in main.py convert that into an
    unavailable response.
    """

    def __init__(self) -> None:
        self.available: bool = False
        self.error: Optional[str] = None
        self.model = None
        self.feature_names: List[str] = list(DEFAULT_FEATURE_NAMES)
        self.model_version: str = "unavailable"

        try:
            if not _MODEL_PATH.exists():
                raise FileNotFoundError(
                    f"model not found at {_MODEL_PATH}. "
                    f"Run ml/training/train.py to produce the artifact."
                )
            self.model = joblib.load(_MODEL_PATH)

            if _FEATURE_NAMES_PATH.exists():
                self.feature_names = json.loads(_FEATURE_NAMES_PATH.read_text())
            else:
                # Fall back to the baked-in order if the file is missing.
                # This preserves backwards compatibility if the feature
                # order file is ever accidentally deleted.
                self.feature_names = list(DEFAULT_FEATURE_NAMES)

            if _METADATA_PATH.exists():
                meta = json.loads(_METADATA_PATH.read_text())
                self.model_version = meta.get("modelVersion", "unknown")
            else:
                self.model_version = "trustvex-url-rf-v1"

            self.available = True
        except Exception as e:
            self.available = False
            self.error = f"{type(e).__name__}: {e}"
            self.model_version = "unavailable"

    def expected_feature_names(self) -> List[str]:
        return list(self.feature_names)

    def predict(self, feature_values: dict) -> float:
        """
        Predict a risk probability in [0, 1]. Raises RuntimeError if the
        model is not available.
        """
        if not self.available or self.model is None:
            raise RuntimeError(
                f"Model unavailable: {self.error or 'not loaded'}"
            )

        # Assemble the feature vector in the exact order the model expects.
        # Missing values would be a client bug, but we defend anyway.
        vec = []
        for name in self.feature_names:
            if name not in feature_values:
                raise RuntimeError(
                    f"missing feature '{name}' in request payload"
                )
            val = feature_values[name]
            if val is None:
                # A null in a URL-string feature should never occur for a
                # valid URL, but if it does, treat it as 0 (the trained
                # model never saw nulls). Logging this to stdout would
                # create noise; the caller can inspect the response.
                val = 0
            elif isinstance(val, bool):
                val = 1 if val else 0
            vec.append(float(val))

        X = np.asarray([vec], dtype=float)
        prob = float(self.model.predict_proba(X)[0, 1])

        # Defensive clamp. The model's predict_proba is bounded by [0, 1]
        # already, but this makes the invariant explicit.
        if prob < 0.0:
            prob = 0.0
        elif prob > 1.0:
            prob = 1.0
        return prob