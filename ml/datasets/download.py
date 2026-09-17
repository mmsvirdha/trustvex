# ml/datasets/download.py
#
# Validates that the Kaggle phishing-site-urls CSV has been placed at the
# expected path and records its provenance in a manifest.
#
# NO NETWORK ACCESS. Kaggle requires a browser login to download the
# dataset, so this script does not attempt to fetch it. The user downloads
# it manually, unzips it, and places the CSV at:
#
#     ml/datasets/raw/kaggle-phishing-site-urls.csv
#
# IMPORTANT: the CSV is NOT quoted, and some URLs contain commas in their
# path or query string. We therefore split each row at the LAST comma:
# everything before the final comma is the URL, everything after is the
# label. This is the only correct way to parse this file without a real
# CSV parser, and it works because the label is always exactly one of
# the two known values.
#
# Run (from project root, venv active):
#     python ml\datasets\download.py

import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "raw"
CSV_PATH = RAW_DIR / "kaggle-phishing-site-urls.csv"
MANIFEST_PATH = ROOT / "download-manifest.json"

KNOWN_LABELS = {"good", "bad"}


def log(msg: str) -> None:
    print(f"[download] {msg}", flush=True)


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def split_url_and_label(line: str) -> tuple[str, str] | None:
    """
    Split a raw CSV line into (url, label) by the LAST comma.
    Returns None if the line has no comma or the label is not recognized.
    """
    idx = line.rfind(",")
    if idx < 0:
        return None
    url = line[:idx].strip()
    label = line[idx + 1:].strip()
    if label not in KNOWN_LABELS:
        return None
    if not url:
        return None
    return url, label


def main() -> None:
    if not CSV_PATH.exists():
        log(f"missing input file: {CSV_PATH}")
        log("")
        log("Steps to fix:")
        log("  1. Download the dataset from Kaggle:")
        log("     https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls")
        log("  2. Unzip the archive.")
        log("  3. Place the CSV at exactly this path:")
        log(f"     {CSV_PATH}")
        log("  4. Re-run this script.")
        sys.exit(2)

    log(f"inspecting {CSV_PATH}")
    size_bytes = CSV_PATH.stat().st_size
    log(f"file size: {size_bytes:,} bytes")

    log("computing sha256 ...")
    file_hash = sha256_of_file(CSV_PATH)
    log(f"sha256: {file_hash}")

    log("scanning rows ...")
    label_counts: Counter = Counter()
    total_lines = 0
    valid_rows = 0
    invalid_rows = 0
    sample_row: list[str] = []

    with open(CSV_PATH, "r", encoding="utf-8", errors="replace") as f:
        header_line = f.readline().rstrip("\n")
        header_cols = [c.strip() for c in header_line.split(",")]
        log(f"header: {header_cols}")

        for line in f:
            line = line.rstrip("\n").rstrip("\r")
            if not line:
                continue
            total_lines += 1
            parsed = split_url_and_label(line)
            if parsed is None:
                invalid_rows += 1
                continue
            url, label = parsed
            valid_rows += 1
            label_counts[label] += 1
            if not sample_row:
                sample_row = [url, label]

    log(f"total lines: {total_lines:,}")
    log(f"valid rows: {valid_rows:,}")
    log(f"invalid rows (no valid label at end): {invalid_rows:,}")
    for label in ("good", "bad"):
        count = label_counts.get(label, 0)
        pct = 100.0 * count / valid_rows if valid_rows else 0
        log(f"  label {label!r}: {count:,} ({pct:.1f}%)")
    log(f"sample row: {sample_row}")

    manifest = {
        "inspectedAt": datetime.now(timezone.utc).isoformat(),
        "source": "Kaggle taruntiwarihp/phishing-site-urls",
        "sourcePage": "https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls",
        "file": {
            "path": str(CSV_PATH.relative_to(ROOT)),
            "sizeBytes": size_bytes,
            "sha256": file_hash,
        },
        "columns": header_cols,
        "totalLines": total_lines,
        "validRows": valid_rows,
        "invalidRows": invalid_rows,
        "labelCounts": dict(label_counts),
        "parsingStrategy": (
            "Split each line at the LAST comma. This handles URLs that "
            "contain commas in their path or query string. The label is "
            "always the substring after the final comma and must be "
            "exactly 'good' or 'bad'; anything else is counted as invalid "
            "and skipped."
        ),
        "notes": [
            "Labels are inherited from the Kaggle dataset and are NOT independently verified by TRUSTVEX.",
            "The 'good' class is referred to as 'labeled non-phishing (per source)' in all downstream artifacts.",
            "The 'bad' class is referred to as 'labeled phishing (per source)' in all downstream artifacts.",
        ],
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
    log(f"wrote {MANIFEST_PATH.name}")
    log("done.")


if __name__ == "__main__":
    main()