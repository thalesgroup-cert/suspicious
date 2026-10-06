# Long-running inference server; built and started by hand (see the README),
# never launched by Cortex itself.
FROM python:3.14-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY

RUN apt-get update -y && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /worker/AiMailPublicAnalyzer

# Build context is Analyzers/AiMailPublicAnalyzer/.
COPY requirements.txt requirements-inference.txt ./
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --upgrade pip
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
RUN http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}" uv pip install --system --no-cache -r requirements-inference.txt

# server.py imports mail_public_analysis and ResNetMLP as siblings via cwd.
COPY . .

EXPOSE 8091

CMD ["uvicorn", "inference_server.server:app", "--host", "0.0.0.0", "--port", "8091"]
