# Persistent inference server image - same base pattern as the parent
# AIMailAnalyzer/Dockerfile (Cortex one-shot analyzer), but this one stays
# running: it's built and launched separately (see
# deployment/compose_apps.yaml's ai_inference service), never invoked by
# Cortex's docker job runner directly.
FROM python:3.14-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY

RUN apt-get update -y && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /worker/AIMailAnalyzer

# Build context is Analyzers/AIMailAnalyzer/ (same as the main Dockerfile) so
# requirements.txt/-inference.txt are found directly - see
# compose_apps.yaml's ai_inference.build.context.
COPY requirements.txt requirements-inference.txt ./
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --upgrade pip
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache -r requirements-inference.txt

# Whole AIMailAnalyzer/ tree - mail_analysis.py, ResNetMLP.py, models/,
# models_public/, vectorizers/, this inference_server/ subfolder - server.py
# imports the first two as siblings via cwd, not a package install.
COPY . .

EXPOSE 8090

CMD ["uvicorn", "inference_server.server:app", "--host", "0.0.0.0", "--port", "8090"]
