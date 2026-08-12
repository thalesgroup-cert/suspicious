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
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# set work directory
WORKDIR /worker/

# install dependencies
# uv/pip only honor lowercase http_proxy/https_proxy - Docker's own proxy
# injection (~/.docker/config.json) only sets the uppercase ARGs, which is
# why apt-get above works (apt reads it via a separate mechanism) but uv
# doesn't unless explicitly passed here (same fix as Suspicious/Dockerfile
# and email-feeder/Dockerfile).
#
# requirements-client.txt, NOT requirements.txt: ai_mail_classifier.py is a
# thin HTTP client now (see inference_server/ for where model loading
# actually happens) - no torch/sentence_transformers needed in this image
# at all, which is most of what made every Cortex job's container slow to
# start. Keep this image light; the heavy ML deps live in the persistent
# inference_server/ image instead.
COPY requirements-client.txt .
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --upgrade pip
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache -r requirements-client.txt

COPY . /worker/AIMailAnalyzer/

# Expose the application
ENTRYPOINT ["python","AIMailAnalyzer/ai_mail_classifier.py"]
