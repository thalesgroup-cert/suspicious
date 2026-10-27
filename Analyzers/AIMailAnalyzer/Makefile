# Convenience targets for building / testing the AIMailAnalyzer images from this
# folder. The images are normally built by `docker compose` from deployment/
# (see the ai_inference service there); these are for working on the analyzer.
#
# HTTP_PROXY / HTTPS_PROXY are taken from the environment when set - never
# hard-code a proxy address in this file.

PROXY_ARGS := --build-arg HTTP_PROXY="$(HTTP_PROXY)" --build-arg HTTPS_PROXY="$(HTTPS_PROXY)"

.PHONY: build build-inference test

## Thin Cortex analyzer client image (what analyzers.json points at)
build:
	docker build $(PROXY_ARGS) -t aimailanalyzer:local .

## Persistent inference server image (compose service: ai_inference)
build-inference:
	docker build $(PROXY_ARGS) -t aimailanalyzer-inference:local -f inference_server/Dockerfile .

## Unit tests (client tests need only requirements-client.txt + pytest;
## server tests also need requirements-inference.txt)
test:
	python -m pytest tests -v
