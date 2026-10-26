#########
# FINAL #
#########

# pull official base image
FROM python:3.14-slim

# Build-time proxy only (not baked into the running container's env).
ARG HTTP_PROXY
ARG HTTPS_PROXY

RUN apt-get update -y && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# set work directory
WORKDIR /worker/

# install dependencies
COPY requirements.txt .
RUN uv pip install --system --upgrade pip
RUN uv pip install --system --no-cache -r requirements.txt

COPY . /worker/MailHeaderAnalyzer/

# Run as an unprivileged user: a compromised analyzer must not be root in its
# container. Cortex mounts the job directory read-write; if a deployment's job
# directory is not writable by this uid, fix the directory, not the user.
RUN useradd --system --uid 1001 --no-create-home --shell /usr/sbin/nologin analyzer
USER 1001:1001

# Expose the application
ENTRYPOINT ["python","MailHeaderAnalyzer/mail_header_analyzer.py"]
