# ml/service/schemas.py
#
# Pydantic models for the TRUSTVEX ML service.
#
# The service now consumes exactly the 12 URL-string features the trained
# model was built on (see ml/training/train.py, FEATURE_NAMES). The full
# 45-feature vector remains the report's internal representation in the
# Node scanner, but it is not what the ML service consumes.
#
# If the feature contract changes, bump FEATURE_SCHEMA_VERSION and update
# both this file and ml/datasets/FEATURE_CONTRACT.md.

from typing import Optional
from pydantic import BaseModel, Field


class UrlFeatureVectorV1(BaseModel):
    """
    12 URL-string features used by trustvex-url-rf-v1.
    Field names must match feature_names_v1.json exactly.
    """

    # Numeric (non-negative integers)
    url_length: int = Field(..., ge=0)
    hostname_length: int = Field(..., ge=0)
    path_length: int = Field(..., ge=0)
    query_length: int = Field(..., ge=0)
    subdomain_count: int = Field(..., ge=0)
    digit_count: int = Field(..., ge=0)
    special_char_count: int = Field(..., ge=0)

    # Booleans
    has_ip_hostname: bool
    has_punycode: bool
    has_embedded_credentials: bool
    has_unusual_port: bool

    # Numeric (non-negative integer)
    suspicious_keyword_count: int = Field(..., ge=0)


class PredictRequest(BaseModel):
    """Request body for POST /predict."""

    schema_version: str = Field(
        ...,
        description="Must be '1.0'. The service refuses any other version.",
    )
    features: UrlFeatureVectorV1


class PredictResponse(BaseModel):
    """Response body for POST /predict."""

    status: str = Field(
        ...,
        description="'ok' when a prediction is returned; 'unavailable' otherwise.",
    )
    risk_probability: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Probability in [0, 1]. Present only when status == 'ok'.",
    )
    model_version: str = Field(
        ...,
        description="Identifier of the model that produced the prediction, or 'unavailable'.",
    )
    error: Optional[str] = Field(
        None,
        description="Populated only when status == 'unavailable'.",
    )


class HealthResponse(BaseModel):
    """Response body for GET /health."""

    status: str
    model_version: str
    schema_version: str
    model_available: bool