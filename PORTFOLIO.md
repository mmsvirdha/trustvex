# TRUSTVEX — Portfolio Summary

**Website Trust & Risk Intelligence Platform**

A full-stack security tool that analyzes a URL across six independent
signal sources and produces an explainable risk report — backed by a
live rule engine, a trained ML classifier, and a test suite you can run
yourself.

## The problem it solves

"Should I trust this link?" is a hard question. Existing tools tend to
give a single verdict: "safe" or "malicious." Both can be wrong.
Malicious sites use valid HTTPS. New legitimate sites have no reputation
history. A one-word answer is worse than no answer.

TRUSTVEX answers differently: it collects evidence from independent
sources, weights each signal, shows its reasoning, and reports
uncertainty honestly.

## What it does

Given a URL, TRUSTVEX:

1. Parses it for structural risk indicators (IP-literal hosts, punycode,
   embedded credentials, suspicious keywords, excessive subdomains)
2. Resolves real DNS records (A, AAAA, CNAME, MX, NS, TXT, CAA)
3. Opens a live TLS connection and inspects the actual certificate
4. Follows the redirect chain manually, re-validating each hop
5. **Renders the page in headless Chromium** (Playwright) — sees content
   injected by client-side JavaScript, which static HTML parsing misses
6. Queries **URLhaus** (abuse.ch) for live threat intelligence
7. Produces a versioned **45-feature vector** as the ML input contract
8. Runs a rule engine that produces a weighted, explainable trust score
9. Sends 12 URL-string features to a **Python ML microservice** running
   a RandomForest classifier trained on 40,000 labeled URLs
10. Renders a unified report with the score, the ML probability, every
    risk factor, every positive signal, every limitation, and the
    evidence behind each

## Engineering highlights

- **Two-layer SSRF defense.** Every outbound HTTP request resolves DNS
  through a blocklist guard *at connect time* per hop, closing the
  DNS-rebinding window. The browser crawler additionally intercepts
  every request the page makes — including XHR calls from page
  JavaScript — and re-validates it before Chromium sends it.
- **Graceful degradation everywhere.** If URLhaus is down, the scan
  continues. If the Python ML service is unreachable, the scan
  completes with the ML section marked unavailable. No single data
  source can take down a scan.
- **Versioned feature schema.** Adding a feature bumps the schema
  version; old reports keep their original version. Missing data is
  represented as `null` — never as `0` — so downstream consumers can
  distinguish "not measured" from "measured zero."
- **Leakage-safe ML training.** Train/val/test split is grouped by
  registrable domain using the Public Suffix List — no domain appears
  in two splits. This tests generalization to unseen domains, which is
  the metric that matters for a URL classifier.
- **Honest metrics.** The RandomForest reports test F1 of 0.663 and
  ROC-AUC of 0.774. Mediocre numbers, reported verbatim, with a
  documented explanation of why and what v2 would need.
- **83 automated tests** across TypeScript and Python, all offline.

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS |
| Backend | Next.js API routes, Node.js |
| Browser automation | Playwright (headless Chromium) |
| Database | SQLite via `node:sqlite` |
| Threat intel | URLhaus (abuse.ch) |
| ML service | Python 3.11, FastAPI, scikit-learn |
| ML model | RandomForest (sklearn) |
| Data prep | pandas, PyArrow, tldextract (PSL) |

## Reproducing the ML model

```bash
# 1. Download the Kaggle phishing-site-urls dataset manually
# 2. Place it at ml/datasets/raw/kaggle-phishing-site-urls.csv
python ml/datasets/download.py    # inspect + hash
python ml/datasets/prepare.py     # canonicalize + dedup + split
python ml/training/train.py       # train + evaluate + save artifact
