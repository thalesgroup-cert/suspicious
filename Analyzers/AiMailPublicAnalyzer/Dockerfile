#########
# FINAL #
#########

# pull official base image
FROM python:3.14-slim

# Build-time proxy only - not baked into the running container's env.
ARG HTTP_PROXY
ARG HTTPS_PROXY

RUN apt-get update -y && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# set work directory
WORKDIR /worker/

# requirements-client.txt, NOT requirements.txt: ai_mail_public_classifier.py
# is a thin HTTP client - no torch/sentence_transformers needed in this
# image at all (see inference_server/ for where model loading happens).
COPY requirements-client.txt .
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --upgrade pip
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache -r requirements-client.txt

COPY . /worker/AiMailPublicAnalyzer/

# Expose the application
ENTRYPOINT ["python","AiMailPublicAnalyzer/ai_mail_public_classifier.py"]
