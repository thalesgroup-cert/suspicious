# Persistent inference server image. Built from Analyzers/AIMailAnalyzer/ as
# the build context (see deployment/docker-compose.override.yml's ai_inference
# service). A long-running server on suspicious_net.
FROM python:3.14-slim

# Build-time proxy only.
ARG HTTP_PROXY
ARG HTTPS_PROXY

RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /worker/AIMailAnalyzer

# requirements-inference.txt pulls in requirements.txt (-r), so both are needed.
COPY requirements.txt requirements-inference.txt ./
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --upgrade pip
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache -r requirements-inference.txt

# The files the server imports as siblings via cwd (mail_analysis.py,
# mail_archive.py, ResNetMLP.py), the inference_server/ package, and the repo's
# small tokenizer / sentence-transformers config files for the vectorizer.
# Model weights are deliberately NOT copied in: models/ is
# bind-mounted at runtime (compose), so the monthly retrain can promote new
# weights without rebuilding this image, and the server hot-reloads them.
COPY mail_analysis.py mail_archive.py ResNetMLP.py ./
COPY inference_server/ ./inference_server/
# The retrain recipe, gate and bundle format: the /v2/train worker imports them.
COPY training/ ./training/
COPY vectorizers/ ./vectorizers/

# The vectorizer's own weights are excluded from the build context
# (.dockerignore) — always the same public checkpoint, so fetch it here.
# Without this step SentenceTransformer() fails at startup (only the tokenizer
# files are in the repo) and every classify call answers 503.
RUN VEC=/worker/AIMailAnalyzer/vectorizers/paraphrase-multilingual-mpnet-base-v2 && \
    BASE=https://huggingface.co/sentence-transformers/paraphrase-multilingual-mpnet-base-v2/resolve/main && \
    mkdir -p "$VEC/1_Pooling" && \
    curl -fL --retry 3 -o "$VEC/model.safetensors" "$BASE/model.safetensors" && \
    curl -fL --retry 3 -o "$VEC/config.json" "$BASE/config.json" && \
    curl -fL --retry 3 -o "$VEC/1_Pooling/config.json" "$BASE/1_Pooling/config.json"

# Everything the server needs is on disk by now: never let transformers /
# huggingface_hub try the network at runtime (on a restricted egress path that
# turns into long hangs at startup instead of a clear "file missing" error).
# HF_HOME points at a writable dir for the non-root user.
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HOME=/tmp/huggingface \
    TOKENIZERS_PARALLELISM=false \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10001 --no-create-home inference
USER inference

EXPOSE 8090

# 503 until the vectorizer and the "personal" models are loaded, so the long
# start_period covers the cold load.
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8090/health', timeout=5)" || exit 1

# ONE uvicorn worker, on purpose: the training job controller (one job at a time, state in memory,
# sweep of leftover job directories at the first job) lives in this process. No --workers.
CMD ["uvicorn", "inference_server.server:app", "--host", "0.0.0.0", "--port", "8090"]
