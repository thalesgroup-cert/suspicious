#########
# FINAL #
#########

# pull official base image
FROM python:3.14-slim

# Build-time proxy only (not baked into the running container's env like the
# old ENV did — that routed every runtime outbound call through a proxy IP
# that only exists on one network).
ARG HTTP_PROXY
ARG HTTPS_PROXY

RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# set work directory
WORKDIR /worker/

# install dependencies
COPY requirements.txt .
RUN uv pip install --system --upgrade pip
RUN uv pip install --system --no-cache torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
RUN uv pip install --system --no-cache -r requirements.txt

COPY . /worker/AIMailAnalyzer/

# The vectorizer's own weights are excluded from the build context
# (.dockerignore) — always the same public checkpoint, so fetch it here
# instead of requiring everyone to hand-download it first (see
# vectorizers/*/model.safetensors.template.md, which used to be the only
# instruction for this step).
RUN VEC=/worker/AIMailAnalyzer/vectorizers/paraphrase-multilingual-mpnet-base-v2 && \
    BASE=https://huggingface.co/sentence-transformers/paraphrase-multilingual-mpnet-base-v2/resolve/main && \
    mkdir -p "$VEC/1_Pooling" && \
    curl -fL -o "$VEC/model.safetensors" "$BASE/model.safetensors" && \
    curl -fL -o "$VEC/config.json" "$BASE/config.json" && \
    curl -fL -o "$VEC/1_Pooling/config.json" "$BASE/1_Pooling/config.json"

# Expose the application
ENTRYPOINT ["python","AIMailAnalyzer/ai_mail_classifier.py"]
