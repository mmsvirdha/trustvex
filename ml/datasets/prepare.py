# ml/datasets/prepare.py
#
# Transforms the Kaggle phishing-site-urls CSV into a cleaned, 12-feature
# dataset with a leakage-safe grouped split.
#
# Steps:
#   1. Load the CSV, map 'good' -> 0 and 'bad' -> 1.
#   2. Canonicalize URLs. Some URLs in the source CSV lack a scheme
#      (e.g. "example.com/path"); we prepend "http://" so urlsplit can
#      extract the hostname. Without this, ~99% of rows would be dropped
#      as unparseable.
#   3. Exact-URL deduplication within each class.
#   4. Cap per class (default 20,000).
#   5. Compute registrable domain for each URL (Public Suffix List).
#   6. Compute the 12 features.
#   7. Group-split by registrable domain (70/15/15), stratified by class.
#   8. Write prepared.parquet + prepare-manifest.json.
#
# IMPORTANT: the CSV is NOT quoted, and some URLs contain commas in their
# path or query string. We therefore split each row at the LAST comma:
# everything before the final comma is the URL, everything after is the
# label.
#
# No training. No model. No change to production code.
#
# Run (from project root, venv active):
#     python ml\datasets\download.py
#     python ml\datasets\prepare.py

import argparse
import hashlib
import json
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import pandas as pd
import tldextract

ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "raw"
DERIVED_DIR = ROOT / "derived"
DERIVED_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = RAW_DIR / "kaggle-phishing-site-urls.csv"
MANIFEST_PATH = ROOT / "prepare-manifest.json"
OUTPUT_PARQUET = DERIVED_DIR / "prepared.parquet"

RANDOM_SEED = 42
MAX_SAMPLES_PER_CLASS = 20_000
SPLIT_TRAIN = 0.70
SPLIT_VAL = 0.15
SPLIT_TEST = 0.15

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "banking", "billing", "password", "wallet", "recover", "unlock", "suspended",
]

URL_TYPICAL_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    ".:/?&=_-#"
)

_tld = tldextract.TLDExtract(suffix_list_urls=None)


def log(msg: str) -> None:
    print(f"[prepare] {msg}", flush=True)


# ---------- Canonicalization ----------

def normalize_scheme(url: str) -> str:
    """
    The Kaggle dataset stores URLs without a scheme (e.g. 'example.com/path').
    urlparse on a scheme-less string treats the whole thing as a path, so
    parts.hostname is empty and canonicalize_url drops the row. We prepend
    'http://' to any URL that lacks an explicit http/https scheme so the
    parser can extract a hostname.

    This does NOT change the semantics of the URL for our purposes —
    we're only using these URLs for feature extraction, not for actual
    HTTP requests.
    """
    if url.lower().startswith(("http://", "https://")):
        return url
    return "http://" + url


def canonicalize_url(url: str) -> str | None:
    try:
        parts = urlsplit(normalize_scheme(url.strip()))
    except Exception:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    path = parts.path or "/"
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        pairs.sort()
        query = urlencode(pairs)
    else:
        query = ""
    return urlunsplit((scheme, host, path, query, ""))


def registrable_domain(url: str) -> str | None:
    try:
        host = urlsplit(normalize_scheme(url)).hostname
    except Exception:
        return None
    if not host:
        return None
    ext = _tld(host)
    if not ext.domain or not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"


# ---------- Feature extraction ----------

def extract_features(url: str) -> dict:
    parts = urlsplit(normalize_scheme(url))
    host = parts.hostname or ""
    path = parts.path or "/"
    query = parts.query or ""

    ext = _tld(host)
    subdomain = ext.subdomain
    subdomain_count = len(subdomain.split(".")) if subdomain else 0

    digit_count = sum(1 for c in url if c.isdigit())
    special_count = sum(1 for c in url if c not in URL_TYPICAL_CHARS)

    host_no_brackets = host.strip("[]")
    has_ip = _is_ipv4(host_no_brackets) or (":" in host_no_brackets)

    has_punycode = any(label.startswith("xn--") for label in host.split("."))
    has_creds = bool(parts.username or parts.password)
    has_unusual_port = parts.port is not None and parts.port not in (80, 443)

    lowered = url.lower()
    kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered)

    return {
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "subdomain_count": subdomain_count,
        "digit_count": digit_count,
        "special_char_count": special_count,
        "has_ip_hostname": has_ip,
        "has_punycode": has_punycode,
        "has_embedded_credentials": has_creds,
        "has_unusual_port": has_unusual_port,
        "suspicious_keyword_count": kw_count,
    }


def _is_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ---------- Loading ----------

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
    if label not in ("good", "bad"):
        return None
    if not url:
        return None
    return url, label


def load_kaggle() -> tuple[list[str], list[int], dict]:
    """
    Returns (urls, labels, meta) where labels are 0 for 'good' and 1 for 'bad'.
    """
    if not CSV_PATH.exists():
        log(f"missing {CSV_PATH} — run download.py after placing the CSV")
        sys.exit(2)

    urls: list[str] = []
    labels: list[int] = []
    total_lines = 0
    invalid_rows = 0

    with open(CSV_PATH, "r", encoding="utf-8", errors="replace") as f:
        header_line = f.readline().rstrip("\n")
        header = [c.strip() for c in header_line.split(",")]
        log(f"header: {header}")

        for line in f:
            line = line.rstrip("\n").rstrip("\r")
            if not line:
                continue
            total_lines += 1
            parsed = split_url_and_label(line)
            if parsed is None:
                invalid_rows += 1
                continue
            u, lab = parsed
            urls.append(u)
            labels.append(1 if lab == "bad" else 0)

    meta = {
        "totalLines": total_lines,
        "validRows": len(urls),
        "invalidRows": invalid_rows,
    }
    log(f"loaded {len(urls):,} valid rows out of {total_lines:,} total lines "
        f"({invalid_rows:,} invalid)")
    return urls, labels, meta


# ---------- Pipeline helpers ----------

def dedupe_preserve_order(items: Iterable[str]) -> tuple[list[str], int]:
    seen: set[str] = set()
    out: list[str] = []
    dupes = 0
    for u in items:
        if u in seen:
            dupes += 1
            continue
        seen.add(u)
        out.append(u)
    return out, dupes


def stratified_group_split(
    rows: list[dict], train_frac: float, val_frac: float, seed: int
) -> tuple[list[dict], list[dict], list[dict], dict]:
    rng = random.Random(seed)

    by_group: dict[str, list[int]] = {}
    for i, r in enumerate(rows):
        by_group.setdefault(r["group"], []).append(i)

    group_label: dict[str, int] = {}
    for g, idxs in by_group.items():
        counts = Counter(rows[i]["label"] for i in idxs)
        group_label[g] = counts.most_common(1)[0][0]

    groups_by_label: dict[int, list[str]] = {0: [], 1: []}
    for g, lab in group_label.items():
        groups_by_label[lab].append(g)

    train, val, test = [], [], []
    for lab, groups in groups_by_label.items():
        rng.shuffle(groups)
        n = len(groups)
        n_train = int(round(n * train_frac))
        n_val = int(round(n * val_frac))
        tr = groups[:n_train]
        va = groups[n_train:n_train + n_val]
        te = groups[n_train + n_val:]
        for g in tr:
            for i in by_group[g]:
                train.append(rows[i])
        for g in va:
            for i in by_group[g]:
                val.append(rows[i])
        for g in te:
            for i in by_group[g]:
                test.append(rows[i])

    stats = {
        "groups_total": len(by_group),
        "groups_train": len({r["group"] for r in train}),
        "groups_val": len({r["group"] for r in val}),
        "groups_test": len({r["group"] for r in test}),
        "train_rows": len(train),
        "val_rows": len(val),
        "test_rows": len(test),
        "train_label_counts": dict(Counter(r["label"] for r in train)),
        "val_label_counts": dict(Counter(r["label"] for r in val)),
        "test_label_counts": dict(Counter(r["label"] for r in test)),
    }
    return train, val, test, stats


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- Main ----------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--max-per-class", type=int, default=MAX_SAMPLES_PER_CLASS)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    manifest: dict = {
        "preparedAt": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "maxPerClass": args.max_per_class,
        "inputFile": {
            "path": str(CSV_PATH.relative_to(ROOT)),
            "sha256": sha256_of_file(CSV_PATH),
            "sizeBytes": CSV_PATH.stat().st_size,
        },
        "labelNote": (
            "Labels are inherited from the Kaggle dataset and are NOT "
            "independently verified by TRUSTVEX. 'good' is referred to as "
            "'labeled non-phishing (per source)'; 'bad' as 'labeled phishing "
            "(per source)'."
        ),
        "parsingStrategy": (
            "Split each line at the LAST comma. Handles URLs that contain "
            "commas in their path or query string."
        ),
        "schemeNote": (
            "Some URLs in the source CSV lack an explicit scheme. We prepend "
            "'http://' before parsing so that hostname extraction works. "
            "This does not change feature semantics: the URLs are only used "
            "for feature extraction, not for live requests."
        ),
    }

    urls, labels, load_meta = load_kaggle()
    manifest["input"] = load_meta

    # Separate by class
    phishing_urls: list[str] = []
    benign_urls: list[str] = []
    for u, lab in zip(urls, labels):
        if lab == 1:
            phishing_urls.append(u)
        else:
            benign_urls.append(u)

    # Canonicalize
    def canon_all(raw: list[str]) -> tuple[list[str], int]:
        out: list[str] = []
        dropped = 0
        for u in raw:
            c = canonicalize_url(u)
            if c is None:
                dropped += 1
                continue
            out.append(c)
        return out, dropped

    phishing_canon, ph_dropped = canon_all(phishing_urls)
    benign_canon, bn_dropped = canon_all(benign_urls)
    manifest["canonicalization"] = {
        "phishing_dropped_unparseable": ph_dropped,
        "benign_dropped_unparseable": bn_dropped,
    }
    log(f"canonicalized: phishing={len(phishing_canon)} benign={len(benign_canon)}")

    # Dedup
    phishing_dedup, ph_dupes = dedupe_preserve_order(phishing_canon)
    benign_dedup, bn_dupes = dedupe_preserve_order(benign_canon)
    manifest["exactDedup"] = {
        "phishing_removed": ph_dupes,
        "benign_removed": bn_dupes,
        "phishing_kept": len(phishing_dedup),
        "benign_kept": len(benign_dedup),
    }
    log(f"dedup: phishing -{ph_dupes} -> {len(phishing_dedup)}; "
        f"benign -{bn_dupes} -> {len(benign_dedup)}")

    # Cap
    if len(phishing_dedup) > args.max_per_class:
        rng.shuffle(phishing_dedup)
        phishing_dedup = phishing_dedup[: args.max_per_class]
    if len(benign_dedup) > args.max_per_class:
        rng.shuffle(benign_dedup)
        benign_dedup = benign_dedup[: args.max_per_class]
    manifest["afterCapping"] = {
        "phishing": len(phishing_dedup),
        "benign": len(benign_dedup),
    }
    log(f"capped: phishing={len(phishing_dedup)} benign={len(benign_dedup)}")

    # Build rows
    rows: list[dict] = []
    for u in phishing_dedup:
        g = registrable_domain(u)
        if not g:
            continue
        rows.append({"group": g, "label": 1, **extract_features(u)})
    for u in benign_dedup:
        g = registrable_domain(u)
        if not g:
            continue
        rows.append({"group": g, "label": 0, **extract_features(u)})

    # Split
    train, val, test, split_stats = stratified_group_split(
        rows, SPLIT_TRAIN, SPLIT_VAL, args.seed
    )
    manifest["split"] = split_stats
    log(f"split: train={split_stats['train_rows']} "
        f"val={split_stats['val_rows']} test={split_stats['test_rows']}")

    # Leakage check
    train_groups = {r["group"] for r in train}
    val_groups = {r["group"] for r in val}
    test_groups = {r["group"] for r in test}
    assert not (train_groups & val_groups), "train/val group leak"
    assert not (train_groups & test_groups), "train/test group leak"
    assert not (val_groups & test_groups), "val/test group leak"
    log("leakage check: zero registrable-domain overlap between splits")

    # Write
    df_train = pd.DataFrame(train); df_train["split"] = "train"
    df_val = pd.DataFrame(val);     df_val["split"] = "val"
    df_test = pd.DataFrame(test);   df_test["split"] = "test"
    df = pd.concat([df_train, df_val, df_test], ignore_index=True)
    df.to_parquet(OUTPUT_PARQUET, index=False)
    log(f"wrote {OUTPUT_PARQUET} ({len(df)} rows)")

    manifest["outputFile"] = str(OUTPUT_PARQUET.relative_to(ROOT))
    manifest["outputRows"] = len(df)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
    log(f"wrote {MANIFEST_PATH.name}")
    log("done.")


if __name__ == "__main__":
    main()