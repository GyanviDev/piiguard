"""
PII Guard — ML attack detection service.

A FastAPI sidecar that scores prompts as SAFE or ATTACK. The Java proxy calls it and
combines the answer with its own rule layer.

CHANGES FROM THE ORIGINAL
=========================

* **The service was unauthenticated and published to the host.** docker-compose mapped
  port 8000 to the host, so anything that could reach the machine could query the
  classifier directly — which is a free oracle for tuning an attack until it scores
  below the threshold, and a way to burn the sidecar's CPU. The port is no longer
  published, and an optional shared key is enforced when configured.

* **A failed model load crashed the process at import time.** `joblib.load` ran at module
  scope with no error handling, so a missing or corrupt artefact killed the container in a
  restart loop. Worse, the Java side reads any failure as "SAFE", so the visible symptom of
  a crash-looping classifier was... nothing. The proxy carried on with rule-based detection
  only and reported itself healthy. The service now starts, reports `model_loaded: false`
  on its health endpoint, and returns 503 from /predict — a state that is loud instead of
  silent.

* **No input size limit.** An unbounded string went straight into a TF-IDF transform.
  Character n-grams over a multi-megabyte payload is a CPU exhaustion primitive.

* **/model/info exposed model internals** — coefficient shapes, hyperparameters and
  vocabulary size — to anonymous callers. That is reconnaissance for anyone building an
  evasion, so it now requires the same key as everything else.
"""

import logging
import os
from typing import Optional

import joblib
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("piiguard-ml")

MODEL_PATH = os.environ.get("MODEL_PATH", "attack_model.pkl")
API_KEY = os.environ.get("ML_API_KEY", "")
MAX_PROMPT_CHARS = int(os.environ.get("MAX_PROMPT_CHARS", "10000"))

# ============================================================================
# Model loading — deferred failure, not a crash loop
# ============================================================================

model = None
load_error: Optional[str] = None

try:
    model = joblib.load(MODEL_PATH)
    log.info("Model loaded from %s", MODEL_PATH)
except Exception as exc:  # noqa: BLE001 - we genuinely want every failure mode here
    load_error = f"{type(exc).__name__}: {exc}"
    log.error("Failed to load model from %s: %s", MODEL_PATH, load_error)


app = FastAPI(
    title="PII Guard ML Service",
    description="Adversarial prompt classification for the PII Guard proxy",
    version="2.0.0",
    # The interactive docs describe the exact input the classifier accepts and are not
    # something to publish next to a security control.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def require_api_key(x_api_key: str = Header(default="")) -> None:
    """
    Enforced only when ML_API_KEY is set, so local development stays frictionless while a
    deployed sidecar can be locked down. Comparison is constant-time: `==` on strings
    short-circuits at the first mismatched byte, and the resulting timing difference leaks
    how much of the key a caller has guessed.
    """
    if not API_KEY:
        return
    import hmac

    if not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key"
        )


class PromptRequest(BaseModel):
    # Pydantic rejects oversized input before it reaches the vectoriser, which is where
    # the CPU cost would be.
    prompt: str = Field(default="", max_length=MAX_PROMPT_CHARS)


class PredictionResponse(BaseModel):
    label: str
    confidence: float
    probabilities: dict


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    detail: Optional[str] = None


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """
    Reports DEGRADED rather than UP when the model is missing. The previous version
    hard-coded `model_loaded=True` and would happily return 200 while broken, which meant
    the Java health check could never detect this failure.
    """
    if model is None:
        return HealthResponse(status="DEGRADED", model_loaded=False, detail=load_error)
    return HealthResponse(status="UP", model_loaded=True)


@app.post("/predict", response_model=PredictionResponse, dependencies=[Depends(require_api_key)])
def predict(request: PromptRequest) -> PredictionResponse:
    """
    Classify a prompt.

    Returns 503 when the model is unavailable instead of a fabricated SAFE verdict. The
    caller must be able to tell "the classifier examined this and approved it" from "there
    was no classifier" — collapsing those two into one answer is how a dead security
    control becomes invisible.
    """
    if model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Classifier unavailable",
        )

    prompt = request.prompt
    if not prompt or not prompt.strip():
        return PredictionResponse(
            label="SAFE", confidence=1.0, probabilities={"SAFE": 1.0, "ATTACK": 0.0}
        )

    probabilities = model.predict_proba([prompt])[0]
    safe_probability = float(probabilities[0])
    attack_probability = float(probabilities[1])

    # Report the probability of the class we predicted, which is what a threshold on the
    # Java side is comparing against.
    label = "ATTACK" if attack_probability >= 0.5 else "SAFE"
    confidence = attack_probability if label == "ATTACK" else safe_probability

    return PredictionResponse(
        label=label,
        confidence=round(confidence, 4),
        probabilities={
            "SAFE": round(safe_probability, 4),
            "ATTACK": round(attack_probability, 4),
        },
    )


@app.get("/model/info", dependencies=[Depends(require_api_key)])
def model_info() -> dict:
    """Model provenance for operators. Behind the same key as /predict."""
    if model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Classifier unavailable"
        )

    metadata = {}
    try:
        import json

        with open("model_metadata.json", encoding="utf-8") as handle:
            metadata = json.load(handle)
    except OSError:
        pass

    return {"model_type": type(model).__name__, "training": metadata}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
