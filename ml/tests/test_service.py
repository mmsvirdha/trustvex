# ml/tests/test_service.py
#
# Tests for the TRUSTVEX ML service skeleton (milestone D1).
#
# These tests exercise the FastAPI surface via the official TestClient,
# which runs the ASGI app in-process — no network, no live server needed.
#
# Run from the project root:
#     python -m pytest ml/tests -v

import copy
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from ml.service.main import app
from ml.service.predictor import MODEL_VERSION


client = TestClient(app)


# ---------- Fixture: a valid minimal feature vector ----------

def valid_feature_payload() -> Dict[str, Any]:
    """
    Returns a full FeatureVector v1.0 payload. All fields are present and
    well-typed. Values are arbitrary but realistic — the stub ignores them,
    but the Pydantic validator does not.
    """
    return {
        "schema_version": "1.0",
        "features": {
            "url_length": 26,
            "hostname_length": 17,
            "path_length": 1,
            "query_length": 0,
            "subdomain_count": 1,
            "digit_count": 0,
            "special_char_count": 0,
            "has_ip_hostname": False,
            "has_punycode": False,
            "has_embedded_credentials": False,
            "has_unusual_port": False,
            "suspicious_keyword_count": 0,

            "dns_status_ok": True,
            "a_record_count": 1,
            "aaaa_record_count": 1,
            "has_mx_record": False,
            "has_caa_record": False,

            "submitted_over_https": True,
            "tls_status_ok": True,
            "tls_authorized": True,
            "tls_hostname_matches": True,
            "tls_days_until_expiry": 48,
            "tls_expires_soon": False,
            "tls_https_available": True,

            "redirect_hop_count": 0,
            "cross_domain_hop_count": 0,
            "has_redirect_chain": False,

            "crawler_status_ok": True,
            "form_count": 1,
            "password_field_count": 0,
            "login_form_detected": False,
            "payment_keyword_detected": False,
            "iframe_count": 0,
            "external_iframe_domain_count": 0,
            "script_count": 2,
            "external_script_domain_count": 0,
            "has_download_links": False,

            "reputation_provider_count": 1,
            "reputation_any_suspicious": False,
            "reputation_any_no_results": True,
            "reputation_any_unavailable": False,

            "confidence_overall": 1.0,
            "components_failed_count": 0,

            "risk_factor_count": 1,
            "positive_signal_count": 3,
        },
    }


# ---------- /health ----------

def test_health_returns_ok() -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["model_version"] == MODEL_VERSION
    assert body["schema_version"] == "1.0"


# ---------- /predict: happy path ----------

def test_predict_valid_feature_vector() -> None:
    r = client.post("/predict", json=valid_feature_payload())
    assert r.status_code == 200
    body = r.json()
    assert body["risk_probability"] == 0.5
    assert body["model_version"] == MODEL_VERSION


def test_predict_is_deterministic_for_identical_input() -> None:
    """The stub must return the same value regardless of input, and the same
    value across calls with identical input."""
    payload = valid_feature_payload()
    r1 = client.post("/predict", json=payload)
    r2 = client.post("/predict", json=payload)
    assert r1.status_code == r2.status_code == 200
    assert r1.json() == r2.json()


def test_predict_ignores_feature_values() -> None:
    """The stub returns the same output for two very different inputs. This
    ensures no accidental dependency on feature values during D1."""
    a = valid_feature_payload()
    b = copy.deepcopy(valid_feature_payload())
    b["features"]["url_length"] = 5000
    b["features"]["has_ip_hostname"] = True
    b["features"]["reputation_any_suspicious"] = True

    ra = client.post("/predict", json=a)
    rb = client.post("/predict", json=b)
    assert ra.json()["risk_probability"] == rb.json()["risk_probability"] == 0.5


# ---------- /predict: nullable feature values ----------

def test_predict_accepts_null_feature_values() -> None:
    """
    Every Optional feature must accept null. Null represents 'the source
    analyzer did not measure this', which is a legitimate state.
    """
    payload = valid_feature_payload()
    for name in [
        "a_record_count", "aaaa_record_count", "has_mx_record", "has_caa_record",
        "tls_authorized", "tls_hostname_matches", "tls_days_until_expiry",
        "tls_expires_soon", "redirect_hop_count", "cross_domain_hop_count",
        "has_redirect_chain", "form_count", "password_field_count",
        "login_form_detected", "payment_keyword_detected", "iframe_count",
        "external_iframe_domain_count", "script_count",
        "external_script_domain_count", "has_download_links",
        "reputation_any_suspicious", "reputation_any_no_results",
        "reputation_any_unavailable",
    ]:
        payload["features"][name] = None

    r = client.post("/predict", json=payload)
    assert r.status_code == 200, r.text


# ---------- /predict: schema_version validation ----------

def test_predict_rejects_wrong_schema_version() -> None:
    payload = valid_feature_payload()
    payload["schema_version"] = "2.0"
    r = client.post("/predict", json=payload)
    assert r.status_code == 400
    assert "schema_version" in r.json()["detail"].lower()


def test_predict_rejects_missing_schema_version() -> None:
    payload = valid_feature_payload()
    del payload["schema_version"]
    r = client.post("/predict", json=payload)
    assert r.status_code == 422  # Pydantic validation error


# ---------- /predict: missing and mistyped fields ----------

def test_predict_rejects_missing_required_feature() -> None:
    payload = valid_feature_payload()
    del payload["features"]["url_length"]
    r = client.post("/predict", json=payload)
    assert r.status_code == 422


def test_predict_rejects_wrong_type() -> None:
    payload = valid_feature_payload()
    payload["features"]["url_length"] = "not a number"
    r = client.post("/predict", json=payload)
    assert r.status_code == 422


def test_predict_rejects_out_of_range_confidence() -> None:
    payload = valid_feature_payload()
    payload["features"]["confidence_overall"] = 1.5
    r = client.post("/predict", json=payload)
    assert r.status_code == 422


def test_predict_rejects_negative_count() -> None:
    payload = valid_feature_payload()
    payload["features"]["form_count"] = -1
    r = client.post("/predict", json=payload)
    assert r.status_code == 422


# ---------- /predict: extra fields ----------

def test_predict_rejects_unknown_feature_field() -> None:
    """
    Pydantic by default ignores extra fields. This test verifies our
    current behavior; if we later want to reject unknown fields, we add
    model_config = ConfigDict(extra='forbid') in schemas.py and this test
    would flip to expecting a 422.
    """
    payload = valid_feature_payload()
    payload["features"]["some_unexpected_field"] = True
    r = client.post("/predict", json=payload)
    # Currently accepted (extra ignored). Changing this is a deliberate
    # schema-evolution decision, not an accident.
    assert r.status_code == 200