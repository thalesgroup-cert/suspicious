#################################################
#                                               #
#   DOCKERFILE – Suspicious                     #
#                                               #
#################################################

#################################################
#               BUILD ARGS                      #
#################################################
ARG PYTHON_VERSION=3.11.14
ARG DEBIAN_SUITE=bookworm
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

################
# BUILDER     #
################
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_SUITE} AS builder

ENV http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    no_proxy=${NO_PROXY} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Build deps (C extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        libffi-dev \
        libldap2-dev \
        libsasl2-dev \
        libmariadb-dev \
        cargo \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv (pinned)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

COPY requirements.txt .

# Install dependencies directly into system python
RUN uv pip install --system --no-cache -r requirements.txt

# Pre-download NLTK data
RUN python - <<EOF
import nltk
nltk.download("stopwords", download_dir="/usr/local/share/nltk_data")
nltk.download("punkt", download_dir="/usr/local/share/nltk_data")
nltk.download("punkt_tab", download_dir="/usr/local/share/nltk_data")
EOF

################
# RUNTIME     #
################
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_SUITE}

LABEL title='Suspicious' \
        description='Suspicious is an AI-powered phishing & threat-analysis platform to automatically inspect, classify, and report suspicious emails, files, URLs, IPs, and hashes built for teams and organizations' \
        source='https://github.com/thalesgroup-cert/suspicious' \
        maintainer='Theo BHANG'

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NLTK_DATA=/usr/local/share/nltk_data

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    lsb-release && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y docker-ce-cli && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Runtime libs only
RUN apt-get update && apt-get install -y --no-install-recommends \
        libldap-common \
        libsasl2-2 \
        wkhtmltopdf \
        libmariadb3 \
        libmagic1 \
        cron \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log \
    && touch /var/log/cron.log

# Copy Python environment from builder
COPY --from=builder /usr/local /usr/local

# Copy NLTK data
COPY --from=builder /usr/local/share/nltk_data /usr/local/share/nltk_data

# Copy application code
COPY . .

WORKDIR /app/Suspicious

EXPOSE 9020