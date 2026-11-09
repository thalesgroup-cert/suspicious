# Convenience targets for building / testing the AIMailAnalyzer image from this
# folder. The images are normally built by `docker compose` from deployment/
# (see the ai_inference service there); these are for working on the analyzer.
#
# HTTP_PROXY / HTTPS_PROXY are taken from the environment when set - never
# hard-code a proxy address in this file.

PROXY_ARGS := --build-arg HTTP_PROXY="$(HTTP_PROXY)" --build-arg HTTPS_PROXY="$(HTTPS_PROXY)"

.PHONY: build-inference test

## Persistent inference server image (compose service: ai_inference)
build-inference:
	docker build $(PROXY_ARGS) -t aimailanalyzer-inference:local -f inference_server/Dockerfile .

## Unit tests (need requirements-inference.txt + pytest + httpx)
test:
	python -m pytest tests -v
