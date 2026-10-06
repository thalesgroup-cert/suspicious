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

# Client deps only: model loading lives in inference_server/.
COPY requirements-client.txt .
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --upgrade pip
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache -r requirements-client.txt

COPY . /worker/AiMailPublicAnalyzer/

# Expose the application
ENTRYPOINT ["python","AiMailPublicAnalyzer/ai_mail_public_classifier.py"]
