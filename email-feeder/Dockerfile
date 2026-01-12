#################################################
#                                               #
#   HARDENED DOCKERFILE – EMAIL FEEDER SERVICE  #
#                                               #
#################################################

# Use Docker Hardened Image (minimal, signed, scanned)
FROM dhi.io/python:3-debian13-sfw-dev AS runtime

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
RUN sfw apt-get update && \
    sfw apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libmariadb3 \
        logrotate \
    && sfw apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -------------------------
# Create non-root user
# -------------------------
RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 --gid appgroup \
       --create-home \
       --shell /usr/sbin/nologin \
       appuser

# -------------------------
# Set working directory
# -------------------------
WORKDIR /app

# -------------------------
# Dependency installation
# (layer caching optimized)
# -------------------------
COPY requirements.txt .

RUN sfw pip install uv && sfw uv pip install --system --upgrade pip\
    && sfw uv pip install --system --no-cache -r requirements.txt

# -------------------------
# Copy application source
# -------------------------
COPY . .

# -------------------------
# Permissions hardening
# -------------------------
RUN chown -R appuser:appgroup /app \
    && chmod -R 755 /app

# -------------------------
# Drop privileges
# -------------------------
USER appuser

# -------------------------
# Runtime configuration
# -------------------------
# ENTRYPOINT ["python", "-m", "main.py"]
