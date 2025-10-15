# Use ARGs for proxies, allowing them to be passed during build time
# These ARGs are only available during the build process.
ARG HTTP_PROXY
ARG HTTPS_PROXY

###########
# BUILDER #
###########
# Use a specific version of the base image for reproducibility
FROM python:3.11 AS builder

# Set proxies ENV vars only within this stage using the build ARGs
ENV http_proxy=${HTTP_PROXY}
ENV https_proxy=${HTTPS_PROXY}

# Set work directory
WORKDIR /app

# Set python environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install build-time system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cargo \
    curl \
    libssl-dev \
    libffi-dev \
    libldap2-dev \
    libsasl2-dev \
    libmariadb-dev \
    pkg-config \
    # Clean up
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install python dependencies using wheels
RUN pip install --no-cache-dir --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

#########
# FINAL #
#########
# Use the same slim base image
FROM python:3.11-slim

# Set ARG/ENV for proxies again if needed *during this stage's build* (e.g., for nltk download)
ENV http_proxy=${HTTP_PROXY}
ENV https_proxy=${HTTPS_PROXY}

# Set work directory
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

# Install only *runtime* system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    libldap-common \
    libsasl2-2 \
    libmariadb3 \
    openssh-client \
    libmagic1 \
    cron \
    # Clean up
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log \
    && touch /var/log/cron.log

# Copy pre-built wheels and requirements from builder stage
COPY --from=builder /wheels /wheels
COPY --from=builder /app/requirements.txt .

# Install Python dependencies from wheels using requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt

# Download NLTK data
RUN python -m nltk.downloader -d /usr/local/share/nltk_data stopwords punkt punkt_tab

# Copy project code *after* dependency installation to leverage caching
COPY . .

# Set the working directory for the application
WORKDIR /app/Suspicious

# Expose the application port
EXPOSE 9020