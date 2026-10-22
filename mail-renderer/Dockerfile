# Isolated Chromium renderer for the mail preview (see server.py).
#
# The official Playwright image carries Chromium and its system libraries. Its
# tag and the pip package must be the same version, or Playwright cannot find
# the browser; bump both together. It runs as root by default, which disables
# Chromium's sandbox, so this image drops to the image's non-root user and the
# compose service applies Playwright's seccomp profile (seccomp_profile.json),
# which is what lets the sandbox work in a container.
ARG PLAYWRIGHT_VERSION=1.63.0
FROM mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-noble

ARG PLAYWRIGHT_VERSION=1.63.0
ARG HTTP_PROXY
ARG HTTPS_PROXY

WORKDIR /app
RUN pip install --no-cache-dir "playwright==${PLAYWRIGHT_VERSION}"
COPY server.py .

USER pwuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4).status == 200 else 1)"
CMD ["python", "server.py"]
