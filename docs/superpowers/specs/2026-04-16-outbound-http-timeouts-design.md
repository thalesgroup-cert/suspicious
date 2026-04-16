# Outbound HTTP Timeouts & Resilience — Design Spec
**Date:** 2026-04-16
**Addresses:** R3 (no timeouts on outbound calls) + P6 (requests calls block Gunicorn workers)
**Approach:** Shared `http_client` module — Option A

---

## Context

All `requests` calls to TheHive in `score_process/score_utils/thehive/phishing.py` (8 call sites) have no `timeout=` argument. Cortex calls go through `cortex4py.Api`, which builds its own `requests.Session` with no timeout set. A slow or unresponsive integration service holds Gunicorn workers indefinitely, stalling the entire platform.

**Already correct — not touched:**
- `tasp/cron/watcher.py` — uses `requests.Session` with `timeout=config.timeout`
- `score_process/scoring/cortex_analyzers/analyzers_services/ai/thehive_utils.py` — `timeout=60` set
- `api/views/oidc.py` — `timeout=5` on all calls

---

## Architecture

```
integration fn
  └─► @RETRY decorator (tenacity: 3 attempts, exponential backoff 1→2→4s)
        └─► circuit breaker (pybreaker: fail_max=5, reset_timeout=60s)
              └─► session.post/get/... (TimeoutHTTPAdapter: connect=5s, read=30s)
```

Single new module `Suspicious/Suspicious/common/http_client.py` owns:
1. `TimeoutHTTPAdapter` — injects default timeout; respects caller-supplied override
2. `make_session()` — returns `requests.Session` with adapter mounted on `http://` and `https://`
3. `BREAKERS` — per-integration `pybreaker.CircuitBreaker` registry
4. `RETRY` — exported `tenacity` retry decorator

---

## Components

### `common/http_client.py`

```python
DEFAULT_CONNECT_TIMEOUT = 5   # seconds
DEFAULT_READ_TIMEOUT    = 30  # seconds

BREAKER_FAIL_MAX      = 5
BREAKER_RESET_TIMEOUT = 60   # seconds

BREAKERS: dict[str, pybreaker.CircuitBreaker] = {
    "cortex":      CircuitBreaker(fail_max=5, reset_timeout=60),
    "thehive":     CircuitBreaker(fail_max=5, reset_timeout=60),
    "misp":        CircuitBreaker(fail_max=5, reset_timeout=60),
    "virustotal":  CircuitBreaker(fail_max=5, reset_timeout=60),
}

def get_breaker(name: str) -> pybreaker.CircuitBreaker: ...
def make_session(connect_timeout=5, read_timeout=30) -> requests.Session: ...

RETRY = tenacity.retry(
    retry=retry_if_exception_type((ConnectionError, Timeout, HTTPError)),
    wait=wait_exponential(multiplier=1, min=1, max=4),
    stop=stop_after_attempt(3),
    reraise=True,
)
```

**Retry scope:** `ConnectionError`, `Timeout`, HTTP 5xx (raise via `response.raise_for_status()`).
**Not retried:** HTTP 4xx (client errors — no point retrying).

### `phishing.py` call-site pattern

```python
_session = make_session()
_breaker = get_breaker("thehive")

@RETRY
def create_new_alert(...):
    with _breaker:
        response = _session.post(url, headers=headers, json=alert_data, verify=certificate_path)
        response.raise_for_status()
        return response.json()
```

Module-level `_session` and `_breaker` — one instance per module lifetime, not per call.

### `cortex_and_job_management.py` — Cortex SDK coverage

`cortex4py.Api` exposes its internal session as `api.session`. Mount `TimeoutHTTPAdapter` post-construction:

```python
adapter = TimeoutHTTPAdapter()
self.api.session.mount("https://", adapter)
self.api.session.mount("http://", adapter)
```

Wrap `get_job_from_api` and `get_report_from_api` static methods with `@RETRY` + `get_breaker("cortex")`.

### `sync_cortex.py`

Wrap the `api.analyzers.find_all(...)` call with `@RETRY` + `get_breaker("cortex")`. Mount `TimeoutHTTPAdapter` on the `Api` session after construction.

---

## Error Handling

| Condition | Behaviour |
|---|---|
| `CircuitBreakerError` (breaker open) | Log `"[breaker:{name}] open — skipping call"` at WARNING, return `None` |
| `tenacity.RetryError` (3 attempts exhausted) | Log with attempt count, re-raise original exception — caught by existing `except Exception` blocks |
| `Timeout` on connect | Log at WARNING, retry kicks in |
| HTTP 5xx | `raise_for_status()` triggers retry |
| HTTP 4xx | `raise_for_status()` raises, not retried, existing error handling catches |

---

## Files Changed

| File | Change |
|---|---|
| `Suspicious/Suspicious/common/__init__.py` | New (empty) |
| `Suspicious/Suspicious/common/http_client.py` | New — `TimeoutHTTPAdapter`, `make_session`, `BREAKERS`, `RETRY` |
| `Suspicious/Suspicious/common/tests/__init__.py` | New (empty) |
| `Suspicious/Suspicious/common/tests/test_http_client.py` | New — unit + integration smoke tests |
| `Suspicious/Suspicious/score_process/score_utils/thehive/phishing.py` | Replace 8 bare `requests.*` with `_session` + `@RETRY` + `_breaker` |
| `Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py` | Mount `TimeoutHTTPAdapter` on `self.api.session`; wrap `get_job_from_api` / `get_report_from_api` |
| `Suspicious/Suspicious/tasp/cron/sync_cortex.py` | Mount adapter; wrap `find_all` call |
| `Suspicious/requirements.txt` | Add `tenacity>=8.2`, `pybreaker>=1.0` |

---

## Testing

**Unit tests (`test_http_client.py`):**
- `TimeoutHTTPAdapter` injects timeout when none passed
- `TimeoutHTTPAdapter` respects caller-supplied timeout (no override)
- `make_session()` mounts adapter on `http://` and `https://`
- `BREAKERS` has all 4 keys with correct `fail_max` / `reset_timeout`
- Transient `ConnectionError` × 1 → retries → success
- `ConnectionError` × 3 → `RetryError` raised
- 5xx response → retried; 4xx → not retried
- 5 consecutive failures → breaker opens → 6th call raises `CircuitBreakerError` immediately

**Integration smoke (using `responses` library):**
- `create_new_alert` with mocked 200 → returns alert dict
- `create_new_alert` with mocked 500 × 3 → logs, returns `None`

---

## Dependencies Added

```
tenacity>=8.2,<9
pybreaker>=1.0,<2
```

Both have no transitive conflicts with existing requirements.
