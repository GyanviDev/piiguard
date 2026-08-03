# ══════════════════════════════════════════════════════════════════════════════
#  PII Guard — ML classifier sidecar
#
#  Training runs during the build so the image is self-contained and the artefact is
#  immutable: the container that serves predictions cannot drift from the model that
#  was evaluated. This also means a training failure fails the BUILD rather than
#  producing an image that starts and silently answers everything as SAFE — which is
#  exactly what happened while train_model.py had a syntax error in it.
# ══════════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim AS build

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY train_model.py .
RUN python train_model.py

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# scikit-learn and its wheels are the heaviest part of this image; the training script
# and its evaluation output do not need to ship with it.
RUN groupadd --system mlsvc \
 && useradd --system --gid mlsvc --home /app --shell /usr/sbin/nologin mlsvc

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && apt-get update && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY --chown=mlsvc:mlsvc main.py .
COPY --from=build --chown=mlsvc:mlsvc /build/attack_model.pkl /build/model_metadata.json ./

USER mlsvc

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
