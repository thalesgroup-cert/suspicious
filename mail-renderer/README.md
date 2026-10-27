# mail-renderer

Headless Chromium behind a small HTTP API, used by Suspicious to draw the PNG
preview of a reported mail. It is a separate container so a browser bug cannot
reach the rest of the stack; see `docs/operations/deploy.md` ("Mail preview
renderer") for the isolation it runs under.

- `POST /render` with UTF-8 HTML, answers `image/png` (900 px wide, clipped to the
  content, at most 4000 px tall). `GET /health`.
- Limits (env): `RENDER_MAX_HTML_BYTES` 2 MB, `RENDER_PAGE_TIMEOUT_MS` 10000,
  `RENDER_REQUEST_TIMEOUT_S` 30, `RENDER_QUEUE_MAX` 4 (a full queue answers 503),
  `RENDER_WATCHDOG_S` 45 (a stuck render exits the process; the container restarts).
- `seccomp_profile.json` is Playwright's own profile for `v1.63.0`
  (`utils/docker/seccomp_profile.json`, Apache-2.0); replace it when you bump
  `PLAYWRIGHT_VERSION` in the Dockerfile. The image tag and the pip package must
  be the same version.

Tests drive the real browser, so run them in the image, with the same hardening:

```bash
docker build -t mail-renderer:local .
docker run --rm --network none --read-only --tmpfs /tmp:size=256m,mode=1777 -e HOME=/tmp \
  --cap-drop ALL --security-opt no-new-privileges --security-opt seccomp=$PWD/seccomp_profile.json \
  --shm-size=1g --init -v $PWD/test_server.py:/app/test_server.py:ro \
  mail-renderer:local python -m unittest -v test_server
```
