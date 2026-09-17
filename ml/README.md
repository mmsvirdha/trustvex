# TRUSTVEX ML Service

Placeholder ML microservice for TRUSTVEX. Part of **milestone D1** in the
project roadmap. This service will eventually host a trained URL risk
classifier and expose it to the Node.js scanner over HTTP.

**Current state (D1):** the service runs, validates a `FeatureVector v1.0`
payload, and returns a fixed `{risk_probability: 0.5, model_version: "stub"}`.
No real model is loaded. No prediction affects the Node scanner yet.

## Requirements

- Python 3.10+
- pip

## Setup

From the project root (`C:\Users\ADMIN\Desktop\trustvex\trustvex`):

```bat
python -m venv ml\.venv
ml\.venv\Scripts\activate
pip install -r ml\requirements.txt