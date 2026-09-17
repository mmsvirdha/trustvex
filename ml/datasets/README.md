# TRUSTVEX Training Data Pipeline

Design and provenance for the URL-classification training dataset used by
the TRUSTVEX ML model v1.

## What this pipeline builds

A 12-feature vector per URL, from two labeled pools:

- **Positive class (phishing):** PhishTank verified-online URLs
- **Negative class (benign candidates):** Tranco top-100k homepage URLs,
  filtered to exclude any domain that appears in PhishTank or an optional
  blocklist

The pipeline is deterministic given a fixed random seed. Raw data is
never committed. Reproducibility comes from re-running the download and
prepare scripts — see `sources.json` for exact URLs and terms references.

## Terminology (this matters)

- **"Phishing"** — a URL present in PhishTank's verified-online feed.
- **"Benign candidate"** — a homepage URL of a top-100k Tranco domain,
  after filtering. **This is not a confirmed-benign label.** Popularity
  is not safety. Tranco is a ranking, not a ground-truth benign set.
- **"Benign"** (unquoted) is avoided in every document and code comment.
- **URLhaus "no result"** is never used as a benign label.

## Known limitations

- The negative class is popularity-based and distributionally narrow.
- The 70/15/15 grouped evaluation measures generalization to unseen
  registrable domains. It does **not** measure temporal generalization to
  future URLs.
- The Tranco list ID changes periodically. The list ID used at training
  time is recorded in the run manifest.
- PhishTank's verified-online feed is a moving target. Download timestamps
  and row counts are recorded in the manifest.

## Files

- `sources.json` — machine-readable provenance
- `FEATURE_CONTRACT.md` — the 12-feature specification
- `download.py` — fetches PhishTank and Tranco
- `prepare.py` — canonicalization, dedup, filtering, grouping, splitting
- `tests/` — unit tests

## Setup

Kaggle requires a browser login, so this pipeline does not fetch the
dataset automatically. Download once, then let the scripts inspect and
prepare it.

1. Go to https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls
2. Sign in and click **Download**. You'll get a ZIP.
3. Unzip it and place the CSV at:
   `ml/datasets/raw/kaggle-phishing-site-urls.csv`
4. Inspect + hash:
python ml\datasets\download.py

text
This writes `download-manifest.json` with the file's SHA-256, actual
row count, and actual label distribution. No network access.
5. Prepare:
python ml\datasets\prepare.py

text
This writes `derived/prepared.parquet` and `prepare-manifest.json`.
6. Inspect both manifests. The actual numbers in the manifest are what
count — never the Kaggle page's advertised statistics.

## What the labels mean (important)

- The Kaggle dataset labels URLs `good` (non-phishing) and `bad`
(phishing). We map them to `0` and `1` respectively.
- **These labels are inherited from the third-party dataset.** TRUSTVEX
does **not** independently verify them.
- In every output, log, and report, we describe them as
**"labeled phishing (per source)"** and **"labeled non-phishing (per
source)"** — never as "confirmed malicious" or "verified benign."
- URLhaus "no result" is never treated as a benign label. See
`sources.json` for the full list of sources we don't use and why.

