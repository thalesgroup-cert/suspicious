#################################################
#                                               #
#   DOCKERFILE – EMAIL FEEDER SERVICE           #
#                                               #
#################################################
FROM python:3.12-slim AS runtime

# -------------------------
# Build-time arguments
# -------------------------
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG PATH_TO=/app

# -------------------------
# Environment variables
# -------------------------
ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY} \
    PATH_TO=${PATH_TO} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# -------------------------
# System dependencies
# (minimal + no recommends)
# -------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libmariadb3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -------------------------
# Set working directory
# -------------------------
WORKDIR /app

# -------------------------
# Dependency installation
# (layer caching optimized)
# -------------------------
# Install uv (pinned)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

COPY requirements.txt .

# Install dependencies directly into system python
RUN uv pip install --system --no-cache -r requirements.txt

# -------------------------
# Non-root runtime user
# -------------------------
# Service consumes attacker-controlled IMAP/SMTP content; never run as root.
# UID/GID match the Suspicious app pattern; override via build args if needed.
ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd --system --gid ${APP_GID} feeder \
    && useradd --system --uid ${APP_UID} --gid ${APP_GID} \
        --home /app --shell /usr/sbin/nologin feeder

# -------------------------
# Copy application source
# -------------------------
COPY . .

# Ensure runtime user owns app dir (logs, working_path, MinIO temp dirs).
RUN chown -R feeder:feeder /app

USER feeder
