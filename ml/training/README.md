# TRUSTVEX URL-Risk Model v1 — Training

Trains a RandomForest classifier on the 12 URL-string features produced
by `ml/datasets/prepare.py`.

## Model

- **Algorithm:** `sklearn.ensemble.RandomForestClassifier`
- **n_estimators:** 200
- **max_depth:** None (trees grow to full depth; bagging handles overfitting)
- **class_weight:** `balanced`
- **random_state:** 42
- **n_jobs:** -1

No hyperparameter search. One frozen configuration. The test-set metrics
are the headline numbers — not the best of a grid search.

## Features (12)

In the exact order the model expects them:
url_length
hostname_length
path_length
query_length
subdomain_count
digit_count
special_char_count
has_ip_hostname
has_punycode
has_embedded_credentials
has_unusual_port
suspicious_keyword_count

text

See `../datasets/FEATURE_CONTRACT.md` for exact definitions of each.

## Input

`ml/datasets/derived/prepared.parquet` — produced by `prepare.py`.

Columns used:
- the 12 feature columns above
- `label` — 0 for "labeled non-phishing (per source)", 1 for "labeled phishing (per source)"
- `split` — one of `train`, `val`, `test`
- `group` — the registrable domain (used upstream for the leakage-safe split; not used by the model)

## Outputs

All written to `ml/models/`:

- `trustvex_url_rf_v1.joblib` — the trained model
- `trustvex_url_rf_v1.metadata.json` — provenance + measured metrics
- `feature_names_v1.json` — the exact feature order the model expects

## Run

From the project root, venv active:

```bat
python ml\training\train.py
Runtime: a few seconds on 28k training rows × 12 features.

