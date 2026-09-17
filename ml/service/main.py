# ml/service/main.py
#
# TRUSTVEX ML service.
#
# Exposes:
#     GET  /health
#     POST /predict
#
# The predictor is loaded once at process startup. If the trained model
# file is missing or fails to load, the service still starts and every
# /predict returns status="unavailable" — it does NOT crash, and it does
# NOT pretend to predict.
#
# Run locally:
#     uvicorn ml.service.main:app --reload --port 8000
#
# from the project root, with the venv active.

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .predictor import Predictor
from .schemas import (
    HealthResponse,
    PredictRequest,
    PredictResponse,
)

SUPPORTED_SCHEMA_VERSION = "1.0"

app = FastAPI(
    title="TRUSTVEX ML Service",
    version="0.2.0",
    description=(
        "ML service for TRUSTVEX. Accepts the 12 URL-string features used "
        "by trustvex-url-rf-v1 and returns a risk probability. If the "
        "trained model file is missing, /predict returns status='unavailable'."
    ),
)

_predictor = Predictor()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        model_version=_predictor.model_version,
        schema_version=SUPPORTED_SCHEMA_VERSION,
        model_available=_predictor.available,
    )


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest) -> PredictResponse:
    if request.schema_version != SUPPORTED_SCHEMA_VERSION:
        return PredictResponse(
            status="unavailable",
            model_version=_predictor.model_version,
            error=(
                f"Unsupported schema_version '{request.schema_version}'. "
                f"This service only accepts '{SUPPORTED_SCHEMA_VERSION}'."
            ),
        )

    if not _predictor.available:
        return PredictResponse(
            status="unavailable",
            model_version="unavailable",
            error=_predictor.error or "model not loaded",
        )

    try:
        prob = _predictor.predict(request.features.model_dump())
    except Exception as e:
        return PredictResponse(
            status="unavailable",
            model_version=_predictor.model_version,
            error=f"{type(e).__name__}: {e}",
        )

    return PredictResponse(
        status="ok",
        risk_probability=prob,
        model_version=_predictor.model_version,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request, exc: Exception) -> JSONResponse:
    # Ensure JSON on every response, even for unexpected errors.
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal error: {type(exc).__name__}"},
    )