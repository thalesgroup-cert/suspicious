#########
# FINAL #
#########

# Thin Cortex analyzer client: untars the mail and POSTs its body to the
# persistent inference server (inference_server/), so this image carries no
# torch / sentence-transformers / model weights - those live in
# inference_server/Dockerfile's image.

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
COPY requirements-client.txt .
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --upgrade pip
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache -r requirements-client.txt

# Only what the client imports (tests/test_client.py guards that this list
# stays in step: ai_mail_classifier.py must import without numpy/torch).
COPY ai_mail_classifier.py mail_archive.py health.py /worker/AIMailAnalyzer/

# Run as an unprivileged user: a compromised analyzer must not be root in its
# container. ai_mail_classifier.py unpacks the mail archive into ./tmp/ under
# the working directory, so that one directory is handed to the analyzer user;
# HOME points at /tmp for library caches. Weights and code stay root-owned and
# read-only to it.
RUN useradd --system --uid 1001 --no-create-home --shell /usr/sbin/nologin analyzer && \
    mkdir -p /worker/tmp && chown 1001:1001 /worker/tmp
ENV HOME=/tmp
USER 1001:1001

# Expose the application
ENTRYPOINT ["python","AIMailAnalyzer/ai_mail_classifier.py"]
