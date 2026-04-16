# Outbound HTTP Timeouts & Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `timeout=(5, 30)`, `tenacity` retry (3×, exponential backoff), and `pybreaker` circuit breakers to all outbound HTTP calls in the Django backend.

**Architecture:** New `common/http_client.py` owns `TimeoutHTTPAdapter`, `make_session()`, per-integration `BREAKERS` dict, and `RETRY` decorator. `phishing.py` replaces 9 bare `requests.*` calls with a single `_thehive_request()` helper. `cortex_and_job_management.py` and `sync_cortex.py` get timeout adapter mounted on `cortex4py`'s internal session and retry/breaker wrappers.

**Tech Stack:** `tenacity>=8.2,<9`, `pybreaker>=1.0,<2`, `requests` (already installed), Django `unittest.TestCase`

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `Suspicious/Suspicious/common/__init__.py` | Package marker |
| Create | `Suspicious/Suspicious/common/http_client.py` | `TimeoutHTTPAdapter`, `make_session`, `BREAKERS`, `get_breaker`, `RETRY` |
| Create | `Suspicious/Suspicious/common/tests/__init__.py` | Test package marker |
| Create | `Suspicious/Suspicious/common/tests/test_http_client.py` | Unit tests for http_client |
| Modify | `Suspicious/requirements.txt` | Add `tenacity`, `pybreaker` |
| Modify | `Suspicious/Suspicious/score_process/score_utils/thehive/phishing.py` | Replace 9 bare `requests.*` with `_thehive_request()` |
| Create | `Suspicious/Suspicious/score_process/score_utils/thehive/tests/__init__.py` | Test package marker |
| Create | `Suspicious/Suspicious/score_process/score_utils/thehive/tests/test_phishing.py` | Unit tests for phishing.py |
| Modify | `Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py` | Mount `TimeoutHTTPAdapter` on cortex4py session; wrap job/report fetch with retry+breaker |
| Modify | `Suspicious/Suspicious/tasp/cron/sync_cortex.py` | Mount adapter; wrap `find_all` with retry+breaker |

---

### Task 1: Add dependencies

**Files:**
- Modify: `Suspicious/requirements.txt`

- [ ] **Step 1: Add packages to requirements.txt**

In `Suspicious/requirements.txt`, under the `# Request Handling` block, add two lines:

```
# Request Handling
requests==2.32.5
PyJWT==2.12.0
minio==7.2.20
zipstream==1.1.4
tenacity>=8.2,<9
pybreaker>=1.0,<2
```

- [ ] **Step 2: Install and verify**

```bash
cd Suspicious && pip install tenacity pybreaker
python -c "import tenacity, pybreaker; print('OK')"
```

Expected output: `OK`

- [ ] **Step 3: Commit**

```bash
git add Suspicious/requirements.txt
git commit -m "chore: add tenacity and pybreaker for outbound HTTP resilience"
```

---

### Task 2: Create `common` package and TDD `TimeoutHTTPAdapter` + `make_session`

**Files:**
- Create: `Suspicious/Suspicious/common/__init__.py`
- Create: `Suspicious/Suspicious/common/tests/__init__.py`
- Create: `Suspicious/Suspicious/common/http_client.py` (partial — adapter + session only)
- Create: `Suspicious/Suspicious/common/tests/test_http_client.py` (partial)

- [ ] **Step 1: Create package scaffolding**

```bash
mkdir -p Suspicious/Suspicious/common/tests
touch Suspicious/Suspicious/common/__init__.py
touch Suspicious/Suspicious/common/tests/__init__.py
```

- [ ] **Step 2: Write failing tests for `TimeoutHTTPAdapter` and `make_session`**

Create `Suspicious/Suspicious/common/tests/test_http_client.py`:

```python
import unittest
from unittest.mock import MagicMock, patch

import requests
from requests.adapters import HTTPAdapter


class TestTimeoutHTTPAdapter(unittest.TestCase):
    """TimeoutHTTPAdapter injects a default timeout and respects explicit overrides."""

    def _make_adapter(self):
        from common.http_client import TimeoutHTTPAdapter
        return TimeoutHTTPAdapter(connect_timeout=3, read_timeout=10)

    def test_injects_default_timeout_when_none_passed(self):
        """When the caller passes no timeout kwarg, adapter injects (connect, read)."""
        adapter = self._make_adapter()
        captured = {}

        def fake_send(prepared_request, **kwargs):
            captured.update(kwargs)
            return MagicMock(status_code=200)

        with patch.object(HTTPAdapter, "send", side_effect=fake_send):
            adapter.send(MagicMock())

        self.assertEqual(captured.get("timeout"), (3, 10))

    def test_respects_caller_supplied_timeout(self):
        """When the caller passes an explicit timeout, adapter does NOT override it."""
        adapter = self._make_adapter()
        captured = {}

        def fake_send(prepared_request, **kwargs):
            captured.update(kwargs)
            return MagicMock(status_code=200)

        with patch.object(HTTPAdapter, "send", side_effect=fake_send):
            adapter.send(MagicMock(), timeout=(1, 2))

        self.assertEqual(captured.get("timeout"), (1, 2))

    def test_default_values_are_5_and_30(self):
        """Default connect=5, read=30 when no custom values passed."""
        from common.http_client import TimeoutHTTPAdapter, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT
        adapter = TimeoutHTTPAdapter()
        self.assertEqual(adapter.connect_timeout, DEFAULT_CONNECT_TIMEOUT)
        self.assertEqual(adapter.read_timeout, DEFAULT_READ_TIMEOUT)
        self.assertEqual(DEFAULT_CONNECT_TIMEOUT, 5)
        self.assertEqual(DEFAULT_READ_TIMEOUT, 30)


class TestMakeSession(unittest.TestCase):
    """make_session() returns a requests.Session with TimeoutHTTPAdapter mounted."""

    def _make(self, **kwargs):
        from common.http_client import make_session
        return make_session(**kwargs)

    def test_returns_requests_session(self):
        self.assertIsInstance(self._make(), requests.Session)

    def test_adapter_mounted_on_https(self):
        from common.http_client import TimeoutHTTPAdapter
        session = self._make()
        self.assertIsInstance(session.get_adapter("https://example.com"), TimeoutHTTPAdapter)

    def test_adapter_mounted_on_http(self):
        from common.http_client import TimeoutHTTPAdapter
        session = self._make()
        self.assertIsInstance(session.get_adapter("http://example.com"), TimeoutHTTPAdapter)

    def test_custom_timeouts_flow_to_adapter(self):
        session = self._make(connect_timeout=2, read_timeout=15)
        adapter = session.get_adapter("https://example.com")
        self.assertEqual(adapter.connect_timeout, 2)
        self.assertEqual(adapter.read_timeout, 15)
```

- [ ] **Step 3: Run tests — verify they fail with ImportError**

```bash
cd Suspicious && python manage.py test common.tests.test_http_client.TestTimeoutHTTPAdapter common.tests.test_http_client.TestMakeSession -v 2
```

Expected: `ImportError: cannot import name 'TimeoutHTTPAdapter' from 'common.http_client'` (or `ModuleNotFoundError`)

- [ ] **Step 4: Implement `TimeoutHTTPAdapter` and `make_session` in `http_client.py`**

Create `Suspicious/Suspicious/common/http_client.py`:

```python
"""
common/http_client.py
~~~~~~~~~~~~~~~~~~~~~
Shared HTTP client utilities:
  - TimeoutHTTPAdapter  — injects default connect/read timeout
  - make_session()      — returns a Session with the adapter mounted
  - BREAKERS            — per-integration pybreaker.CircuitBreaker registry
  - get_breaker()       — look up a breaker by integration name
  - RETRY               — tenacity retry decorator for transient errors + 5xx
"""
from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter

DEFAULT_CONNECT_TIMEOUT: int = 5   # seconds
DEFAULT_READ_TIMEOUT: int    = 30  # seconds


class TimeoutHTTPAdapter(HTTPAdapter):
    """HTTPAdapter that injects a default timeout when the caller doesn't supply one."""

    def __init__(
        self,
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: int = DEFAULT_READ_TIMEOUT,
        **kwargs,
    ):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        super().__init__(**kwargs)

    def send(self, request, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = (self.connect_timeout, self.read_timeout)
        return super().send(request, **kwargs)


def make_session(
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: int = DEFAULT_READ_TIMEOUT,
) -> requests.Session:
    """Return a requests.Session with TimeoutHTTPAdapter mounted on http:// and https://."""
    session = requests.Session()
    adapter = TimeoutHTTPAdapter(connect_timeout=connect_timeout, read_timeout=read_timeout)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session
```

- [ ] **Step 5: Run tests — verify they pass**

```bash
cd Suspicious && python manage.py test common.tests.test_http_client.TestTimeoutHTTPAdapter common.tests.test_http_client.TestMakeSession -v 2
```

Expected: `Ran 7 tests in ...s` → `OK`

- [ ] **Step 6: Commit**

```bash
git add Suspicious/Suspicious/common/ Suspicious/Suspicious/common/tests/
git commit -m "feat: add TimeoutHTTPAdapter and make_session to common/http_client"
```

---

### Task 3: TDD `BREAKERS`, `get_breaker`, and `RETRY`

**Files:**
- Modify: `Suspicious/Suspicious/common/http_client.py` (append)
- Modify: `Suspicious/Suspicious/common/tests/test_http_client.py` (append)

- [ ] **Step 1: Append failing tests to `test_http_client.py`**

Append to `Suspicious/Suspicious/common/tests/test_http_client.py`:

```python

class TestBreakers(unittest.TestCase):
    """BREAKERS dict has one CircuitBreaker per integration, correctly configured."""

    def test_all_four_integrations_present(self):
        from common.http_client import BREAKERS
        for name in ("cortex", "thehive", "misp", "virustotal"):
            self.assertIn(name, BREAKERS, f"Missing breaker for {name!r}")

    def test_breaker_fail_max_and_reset_timeout(self):
        from common.http_client import BREAKERS, BREAKER_FAIL_MAX, BREAKER_RESET_TIMEOUT
        self.assertEqual(BREAKER_FAIL_MAX, 5)
        self.assertEqual(BREAKER_RESET_TIMEOUT, 60)
        for name, breaker in BREAKERS.items():
            self.assertEqual(breaker.fail_max, BREAKER_FAIL_MAX, name)
            self.assertEqual(breaker.reset_timeout, BREAKER_RESET_TIMEOUT, name)

    def test_get_breaker_returns_same_instance(self):
        from common.http_client import BREAKERS, get_breaker
        self.assertIs(get_breaker("thehive"), BREAKERS["thehive"])

    def test_get_breaker_raises_for_unknown_name(self):
        from common.http_client import get_breaker
        with self.assertRaises(KeyError):
            get_breaker("unknown_integration")


class TestRetryDecorator(unittest.TestCase):
    """RETRY retries on ConnectionError/Timeout/5xx but not 4xx."""

    def setUp(self):
        # Patch tenacity's wait to zero so tests don't sleep
        self._patcher = patch("tenacity.wait_exponential.__call__", return_value=0)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()

    def test_retries_on_connection_error_and_succeeds(self):
        from common.http_client import RETRY
        call_count = 0

        @RETRY
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise requests.ConnectionError("down")
            return "ok"

        self.assertEqual(flaky(), "ok")
        self.assertEqual(call_count, 3)

    def test_raises_after_three_failed_attempts(self):
        from common.http_client import RETRY

        @RETRY
        def always_fails():
            raise requests.ConnectionError("always down")

        with self.assertRaises(requests.ConnectionError):
            always_fails()

    def test_does_not_retry_on_4xx(self):
        from common.http_client import RETRY
        call_count = 0

        @RETRY
        def client_error():
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 404
            raise requests.HTTPError(response=resp)

        with self.assertRaises(requests.HTTPError):
            client_error()

        self.assertEqual(call_count, 1)  # no retry on 4xx

    def test_retries_on_5xx_and_succeeds(self):
        from common.http_client import RETRY
        call_count = 0

        @RETRY
        def server_error():
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 503
            if call_count < 3:
                raise requests.HTTPError(response=resp)
            return "ok"

        self.assertEqual(server_error(), "ok")
        self.assertEqual(call_count, 3)

    def test_retries_on_timeout(self):
        from common.http_client import RETRY
        call_count = 0

        @RETRY
        def timeout_once():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise requests.Timeout("timed out")
            return "ok"

        self.assertEqual(timeout_once(), "ok")
        self.assertEqual(call_count, 2)
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd Suspicious && python manage.py test common.tests.test_http_client.TestBreakers common.tests.test_http_client.TestRetryDecorator -v 2
```

Expected: `ImportError: cannot import name 'BREAKERS' from 'common.http_client'`

- [ ] **Step 3: Append `BREAKERS`, `get_breaker`, and `RETRY` to `http_client.py`**

Append to the bottom of `Suspicious/Suspicious/common/http_client.py`:

```python

import pybreaker
import tenacity
from tenacity import (
    retry_if_exception,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

BREAKER_FAIL_MAX: int      = 5
BREAKER_RESET_TIMEOUT: int = 60  # seconds

BREAKERS: dict[str, pybreaker.CircuitBreaker] = {
    "cortex":     pybreaker.CircuitBreaker(fail_max=BREAKER_FAIL_MAX, reset_timeout=BREAKER_RESET_TIMEOUT),
    "thehive":    pybreaker.CircuitBreaker(fail_max=BREAKER_FAIL_MAX, reset_timeout=BREAKER_RESET_TIMEOUT),
    "misp":       pybreaker.CircuitBreaker(fail_max=BREAKER_FAIL_MAX, reset_timeout=BREAKER_RESET_TIMEOUT),
    "virustotal": pybreaker.CircuitBreaker(fail_max=BREAKER_FAIL_MAX, reset_timeout=BREAKER_RESET_TIMEOUT),
}


def get_breaker(name: str) -> pybreaker.CircuitBreaker:
    """Return the CircuitBreaker for the named integration.

    Raises KeyError if *name* is not registered in BREAKERS.
    """
    if name not in BREAKERS:
        raise KeyError(f"No circuit breaker registered for {name!r}")
    return BREAKERS[name]


def _is_retryable_http_error(exc: BaseException) -> bool:
    """Return True for HTTP 5xx errors only — 4xx are client errors, never retried."""
    return (
        isinstance(exc, requests.HTTPError)
        and getattr(exc, "response", None) is not None
        and exc.response.status_code >= 500
    )


#: Retry decorator for outbound integration calls.
#: Retries on ConnectionError, Timeout, and HTTP 5xx.
#: Does NOT retry on HTTP 4xx or CircuitBreakerError.
#: After 3 attempts the original exception is re-raised (reraise=True).
RETRY = tenacity.retry(
    retry=(
        retry_if_exception_type((requests.ConnectionError, requests.Timeout))
        | retry_if_exception(_is_retryable_http_error)
    ),
    wait=wait_exponential(multiplier=1, min=1, max=4),
    stop=stop_after_attempt(3),
    reraise=True,
)
```

- [ ] **Step 4: Run all http_client tests**

```bash
cd Suspicious && python manage.py test common.tests.test_http_client -v 2
```

Expected: `Ran 16 tests in ...s` → `OK`

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/common/http_client.py Suspicious/Suspicious/common/tests/test_http_client.py
git commit -m "feat: add BREAKERS, get_breaker, and RETRY to common/http_client"
```

---

### Task 4: Fix `phishing.py` — replace bare `requests.*` with resilient helper

**Files:**
- Create: `Suspicious/Suspicious/score_process/score_utils/thehive/tests/__init__.py`
- Create: `Suspicious/Suspicious/score_process/score_utils/thehive/tests/test_phishing.py`
- Modify: `Suspicious/Suspicious/score_process/score_utils/thehive/phishing.py`

- [ ] **Step 1: Create test package**

```bash
mkdir -p Suspicious/Suspicious/score_process/score_utils/thehive/tests
touch Suspicious/Suspicious/score_process/score_utils/thehive/tests/__init__.py
```

- [ ] **Step 2: Write failing tests**

Create `Suspicious/Suspicious/score_process/score_utils/thehive/tests/test_phishing.py`:

```python
"""
Tests for score_process.score_utils.thehive.phishing

These tests patch _thehive_request directly — retry/breaker behaviour is
tested separately in common/tests/test_http_client.py.
"""
import unittest
from unittest.mock import MagicMock, patch

import pybreaker
import requests


class TestCreateNewAlert(unittest.TestCase):

    def _call(self, **overrides):
        from score_process.score_utils.thehive.phishing import create_new_alert
        kwargs = dict(
            ticket_id="REF-001",
            title="Test alert",
            description="Desc",
            severity=2,
            tlp=1,
            pap=1,
            app_name="suspicious",
            thehive_url="https://hive.local",
            api_key="key123",
        )
        kwargs.update(overrides)
        return create_new_alert(**kwargs)

    def test_returns_alert_dict_on_success(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"_id": "~alert42"}

        with patch("score_process.score_utils.thehive.phishing._thehive_request", return_value=mock_resp):
            result = self._call()

        self.assertEqual(result, {"_id": "~alert42"})

    def test_returns_none_on_request_exception(self):
        with patch(
            "score_process.score_utils.thehive.phishing._thehive_request",
            side_effect=requests.ConnectionError("down"),
        ):
            result = self._call()

        self.assertIsNone(result)

    def test_returns_none_on_circuit_breaker_open(self):
        with patch(
            "score_process.score_utils.thehive.phishing._thehive_request",
            side_effect=pybreaker.CircuitBreakerError(),
        ):
            result = self._call()

        self.assertIsNone(result)

    def test_auto_generates_ticket_id_when_none(self):
        """Passing ticket_id=None triggers internal ref generation."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"_id": "~auto"}

        with patch("score_process.score_utils.thehive.phishing._thehive_request", return_value=mock_resp):
            result = self._call(ticket_id=None)

        self.assertEqual(result, {"_id": "~auto"})


class TestGetItemFromId(unittest.TestCase):

    def _call(self, item_id="~42"):
        from score_process.score_utils.thehive.phishing import get_item_from_id
        return get_item_from_id(item_id, "https://hive.local", "key123")

    def test_returns_case_type_and_data(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"_id": "~42", "title": "case"}

        with patch("score_process.score_utils.thehive.phishing._thehive_request", return_value=mock_resp):
            item_type, data = self._call()

        self.assertEqual(item_type, "case")
        self.assertEqual(data["_id"], "~42")

    def test_returns_none_none_when_not_found(self):
        err = requests.HTTPError()
        err.response = MagicMock(status_code=404)

        with patch("score_process.score_utils.thehive.phishing._thehive_request", side_effect=err):
            item_type, data = self._call()

        self.assertIsNone(item_type)
        self.assertIsNone(data)

    def test_returns_none_none_on_breaker_open(self):
        with patch(
            "score_process.score_utils.thehive.phishing._thehive_request",
            side_effect=pybreaker.CircuitBreakerError(),
        ):
            item_type, data = self._call()

        self.assertIsNone(item_type)
        self.assertIsNone(data)


class TestAddObservablesToItem(unittest.TestCase):

    def _call(self):
        from score_process.score_utils.thehive.phishing import add_observables_to_item
        return add_observables_to_item(
            "alert", "~42", [{"dataType": "url", "data": "http://evil.test"}],
            "https://hive.local", "key123",
        )

    def test_posts_each_observable(self):
        mock_resp = MagicMock()
        with patch("score_process.score_utils.thehive.phishing._thehive_request", return_value=mock_resp) as mock_req:
            self._call()
        self.assertEqual(mock_req.call_count, 1)

    def test_skips_invalid_item_type(self):
        from score_process.score_utils.thehive.phishing import add_observables_to_item
        with patch("score_process.score_utils.thehive.phishing._thehive_request") as mock_req:
            add_observables_to_item("invalid", "~42", [{}], "https://hive.local", "key123")
        mock_req.assert_not_called()
```

- [ ] **Step 3: Run tests — verify they fail**

```bash
cd Suspicious && python manage.py test score_process.score_utils.thehive.tests.test_phishing -v 2
```

Expected: `ImportError` or `AttributeError: module 'score_process.score_utils.thehive.phishing' has no attribute '_thehive_request'`

- [ ] **Step 4: Update `phishing.py`**

Replace the top of `Suspicious/Suspicious/score_process/score_utils/thehive/phishing.py` — add imports and module-level helper after the existing config block (after line 44, after `logger = logging.getLogger(...)`):

The new imports to add at the top (alongside existing `import requests`):

```python
import pybreaker
from common.http_client import make_session, get_breaker, RETRY
```

Add these four module-level names after `logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")` (around line 45):

```python
_session = make_session()
_thehive_breaker = get_breaker("thehive")


@RETRY
def _thehive_request(method: str, url: str, **kwargs) -> requests.Response:
    """Execute a TheHive HTTP request with timeout, retry, and circuit breaker.

    Calls response.raise_for_status() so callers get HTTPError on non-2xx.
    CircuitBreakerError is NOT retried by RETRY — it propagates immediately.
    """
    with _thehive_breaker:
        response = _session.request(method, url, **kwargs)
        response.raise_for_status()
        return response
```

- [ ] **Step 5: Update `create_new_alert` in `phishing.py`**

Replace the existing `create_new_alert` function body (lines 52–97) with:

```python
def create_new_alert(ticket_id, title, description, severity, tlp, pap, app_name, thehive_url, api_key, tags=None):
    if ticket_id is None:
        ticket_id = generate_ref()

    try:
        severity = int(severity)
    except (ValueError, TypeError):
        severity = 1

    if tags is None:
        tags = ["suspicious"]

    alert_data = {
        "title": title,
        "description": description,
        "severity": severity,
        "tlp": tlp,
        "pap": pap,
        "type": app_name,
        "source": "suspicious",
        "sourceRef": ticket_id,
        "tags": tags,
        "customFields": {"tha-id": ticket_id},
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    url = f"{thehive_url}/api/v1/alert"
    try:
        response = _thehive_request("POST", url, headers=headers, json=alert_data, verify=certificate_path)
        return response.json()
    except pybreaker.CircuitBreakerError as e:
        update_cases_logger.warning("[breaker:thehive] open — create_new_alert skipped: %s", e)
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP Error creating alert: {e}"
        if e.response is not None and e.response.text:
            error_msg += f"\nResponse: {e.response.text}"
        update_cases_logger.error(error_msg)
    except ValueError as e:
        update_cases_logger.error(f"Error parsing response: {e}")
    except Exception as e:
        update_cases_logger.error(f"Error creating alert: {e}")

    return None
```

- [ ] **Step 6: Update `get_item_from_id` in `phishing.py`**

Replace the existing `get_item_from_id` function (lines 186–201):

```python
def get_item_from_id(item_id, thehive_url, api_key):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    for item_type in ["case", "alert"]:
        url = f"{thehive_url}/api/v1/{item_type}/{item_id}"
        try:
            response = _thehive_request("GET", url, headers=headers, verify=certificate_path)
            return item_type, response.json()
        except pybreaker.CircuitBreakerError as e:
            update_cases_logger.warning("[breaker:thehive] open — get_item_from_id skipped: %s", e)
            return None, None
        except requests.exceptions.HTTPError:
            # Non-200 (e.g. 404 — item is not this type); try next type
            continue
        except requests.exceptions.RequestException as e:
            update_cases_logger.error(f"Error retrieving {item_type} with ID {item_id}: {e}")

    return None, None
```

- [ ] **Step 7: Update `add_observables_to_item` in `phishing.py`**

Replace the existing `add_observables_to_item` function (lines 204–221):

```python
def add_observables_to_item(item_type, item_id, observable_data, thehive_url, api_key):
    if item_type not in ("alert", "case"):
        update_cases_logger.error(f"add_observables_to_item: invalid item_type {item_type!r}, skipping")
        return

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    url = f"{thehive_url}/api/v1/{item_type}/{item_id}/observable"

    for observable in observable_data:
        try:
            _thehive_request("POST", url, headers=headers, json=observable, verify=certificate_path)
        except pybreaker.CircuitBreakerError as e:
            update_cases_logger.warning("[breaker:thehive] open — add_observables_to_item skipped: %s", e)
            return
        except requests.exceptions.RequestException as e:
            update_cases_logger.error(f"Error adding observable {observable.get('data')}: {e}")
```

- [ ] **Step 8: Update `add_attachments_to_item` in `phishing.py`**

Replace the existing `add_attachments_to_item` function (lines 223–244):

```python
def add_attachments_to_item(item_type, item_id, attachment_paths, thehive_url, api_key):
    if item_type not in ("alert", "case"):
        update_cases_logger.error(f"add_attachments_to_item: invalid item_type {item_type!r}, skipping")
        return

    headers = {"Authorization": f"Bearer {api_key}"}
    url = f"{thehive_url}/api/v1/{item_type}/{item_id}/attachments"

    for file_path in attachment_paths:
        try:
            with open(file_path, "rb") as f:
                _thehive_request(
                    "POST", url,
                    headers=headers,
                    files=[("attachments", (os.path.basename(file_path), f))],
                    verify=certificate_path,
                )
        except pybreaker.CircuitBreakerError as e:
            update_cases_logger.warning("[breaker:thehive] open — add_attachments_to_item skipped: %s", e)
            return
        except requests.exceptions.RequestException as e:
            update_cases_logger.error(f"Error adding attachment {file_path}: {e}")
        except Exception as e:
            update_cases_logger.error(f"Error opening attachment {file_path}: {e}")
```

- [ ] **Step 9: Update `add_comment_to_item` in `phishing.py`**

Replace the existing `add_comment_to_item` function (lines 247–295):

```python
def add_comment_to_item(item_type, item_id, comment, thehive_url, api_key):
    if item_type not in ("alert", "case"):
        update_cases_logger.error(f"add_comment_to_item: invalid item_type {item_type!r}, skipping")
        return

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    url_add_comment = f"{thehive_url}/api/v1/{item_type}/{item_id}/comment"
    url_modify_comment = lambda comment_id: f"{thehive_url}/api/v1/comment/{comment_id}/"
    url_query_comments = f"{thehive_url}/api/v1/query?name=get-alert-comments-{item_id}"
    query_comments = {
        "query": [
            {
                "_name": {"alert": "getAlert", "case": "getCase"}[item_type],
                "idOrName": item_id,
            },
            {"_name": "comments"},
            {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
            {"_name": "page", "from": 0, "to": 1},
        ]
    }

    try:
        response = _thehive_request(
            "POST", url_query_comments,
            json=query_comments, headers=headers, verify=certificate_path,
        )
        response_data = response.json()

        if response_data:
            existing = response_data[0]
            too_old = existing["createdAt"] < (datetime.now().timestamp() * 1000) - 600000
            wrong_user = existing["createdBy"] != thehive_config.get("user")
            if too_old or wrong_user:
                _thehive_request("POST", url_add_comment, headers=headers, json=comment, verify=certificate_path)
            else:
                _thehive_request(
                    "PATCH", url_modify_comment(existing["_id"]),
                    headers=headers, json=comment, verify=certificate_path,
                )
        else:
            _thehive_request("POST", url_add_comment, headers=headers, json=comment, verify=certificate_path)

    except pybreaker.CircuitBreakerError as e:
        update_cases_logger.warning("[breaker:thehive] open — add_comment_to_item skipped: %s", e)
    except requests.exceptions.RequestException as e:
        update_cases_logger.error(f"Error querying comments for {item_type} {item_id}: {e}")
        # Fallback: attempt to post a new comment directly
        try:
            _thehive_request("POST", url_add_comment, headers=headers, json=comment, verify=certificate_path)
        except pybreaker.CircuitBreakerError as e2:
            update_cases_logger.warning("[breaker:thehive] open — fallback comment skipped: %s", e2)
        except requests.exceptions.RequestException as e2:
            update_cases_logger.error(f"Error adding comment to {item_type} {item_id}: {e2}")
```

- [ ] **Step 10: Run tests**

```bash
cd Suspicious && python manage.py test score_process.score_utils.thehive.tests.test_phishing -v 2
```

Expected: `Ran 9 tests in ...s` → `OK`

- [ ] **Step 11: Commit**

```bash
git add \
  Suspicious/Suspicious/score_process/score_utils/thehive/phishing.py \
  Suspicious/Suspicious/score_process/score_utils/thehive/tests/
git commit -m "feat(r3+p6): add timeout/retry/breaker to TheHive calls in phishing.py"
```

---

### Task 5: Fix `cortex_and_job_management.py` — timeout adapter + retry/breaker on job/report fetch

**Files:**
- Modify: `Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py`

The cortex4py `Api` class stores its `requests.Session` as `self.__session` (name-mangled). Access it via `api._Api__session`. If cortex4py changes this in a future version, the `AttributeError` is caught and a warning logged — timeout degrades gracefully.

- [ ] **Step 1: Add imports to `cortex_and_job_management.py`**

At the top of the file (after existing imports, around line 14), add:

```python
import pybreaker
from common.http_client import TimeoutHTTPAdapter, get_breaker, RETRY
```

- [ ] **Step 2: Mount `TimeoutHTTPAdapter` on cortex4py session in `CortexJob.__init__`**

In `CortexJob.__init__` (lines 66–70), after `self.api = Api(...)`, add:

```python
        # Mount a timeout adapter on cortex4py's internal requests.Session.
        # cortex4py stores it as a private attribute (_Api__session); if the
        # internal API changes, fall back gracefully.
        if self.api is not None:
            _adapter = TimeoutHTTPAdapter()
            try:
                self.api._Api__session.mount("https://", _adapter)
                self.api._Api__session.mount("http://", _adapter)
            except AttributeError:
                fetch_mail_logger.warning(
                    "Could not mount TimeoutHTTPAdapter on cortex4py session — "
                    "timeout not guaranteed for Cortex calls"
                )
```

Apply the same block in the module-level `API` initialisation (around lines 40–44 where `API = Api(API_URL, API_KEY, proxies={"http": "", "https": ""})` is called). Replace that block with:

```python
try:
    API = Api(API_URL, API_KEY, proxies={"http": "", "https": ""})
    _adapter = TimeoutHTTPAdapter()
    try:
        API._Api__session.mount("https://", _adapter)
        API._Api__session.mount("http://", _adapter)
    except AttributeError:
        fetch_mail_logger.warning(
            "Could not mount TimeoutHTTPAdapter on module-level Cortex API session"
        )
except Exception as e:
    fetch_mail_logger.error(f"Failed to initialize Cortex API: {e}")
    API = None
```

- [ ] **Step 3: Add `_fetch_job` and `_fetch_report` helpers and update static methods**

Add two private module-level functions after the `API` initialisation block (after line ~44):

```python
_cortex_breaker = get_breaker("cortex")


@RETRY
def _fetch_job(api, job_id: str):
    """Fetch a Cortex job by ID with retry and circuit breaker."""
    with _cortex_breaker:
        return api.jobs.get_by_id(job_id)


@RETRY
def _fetch_report(api, job_id: str):
    """Fetch a Cortex job report by ID with retry and circuit breaker."""
    with _cortex_breaker:
        return api.jobs.get_report(job_id)
```

- [ ] **Step 4: Update `CortexJobManager.get_job_from_api` to use `_fetch_job`**

Replace the existing `get_job_from_api` static method (lines 598–610):

```python
    @staticmethod
    def get_job_from_api(job_id):
        for api in [API]:
            if api is None:
                continue
            try:
                job = _fetch_job(api, job_id)
                if job:
                    return job
            except pybreaker.CircuitBreakerError as e:
                update_cases_logger.warning(
                    "[breaker:cortex] open — get_job_from_api skipped for job %s: %s", job_id, e
                )
            except Exception as e:
                update_cases_logger.error(
                    f"Error fetching job {job_id}: {e}", exc_info=True
                )
        return "old_job"
```

- [ ] **Step 5: Update `CortexJobManager.get_report_from_api` to use `_fetch_report`**

Replace the existing `get_report_from_api` static method (lines 613–624):

```python
    @staticmethod
    def get_report_from_api(job_id):
        for api in [API]:
            if api is None:
                continue
            try:
                report = _fetch_report(api, job_id)
                if report:
                    return getattr(report, "report", None)
            except pybreaker.CircuitBreakerError as e:
                update_cases_logger.warning(
                    "[breaker:cortex] open — get_report_from_api skipped for job %s: %s", job_id, e
                )
            except Exception as e:
                update_cases_logger.error(
                    f"Error fetching report for job {job_id}: {e}", exc_info=True
                )
        return None
```

- [ ] **Step 6: Run existing tests to verify no regression**

```bash
cd Suspicious && python manage.py test cortex_job -v 2
```

Expected: `OK` (or same results as before the change — no new failures)

- [ ] **Step 7: Commit**

```bash
git add Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py
git commit -m "feat(r3+p6): mount timeout adapter and add retry/breaker to Cortex job fetch"
```

---

### Task 6: Fix `sync_cortex.py` — timeout adapter + retry/breaker on analyzer sync

**Files:**
- Modify: `Suspicious/Suspicious/tasp/cron/sync_cortex.py`

- [ ] **Step 1: Add imports to `sync_cortex.py`**

After the existing imports (after `from cortex_job.models import Analyzer`), add:

```python
import pybreaker
from common.http_client import TimeoutHTTPAdapter, get_breaker, RETRY
```

- [ ] **Step 2: Add `_fetch_all_analyzers` helper before `sync_cortex_analyzers`**

After the imports, before the `sync_cortex_analyzers` function definition, add:

```python
_cortex_breaker = get_breaker("cortex")


@RETRY
def _fetch_all_analyzers(api):
    """Fetch all remote analyzers with retry and circuit breaker."""
    with _cortex_breaker:
        return api.analyzers.find_all({}, range="all")
```

- [ ] **Step 3: Update `sync_cortex_analyzers` to use the helper and mount the adapter**

Replace the existing `sync_cortex_analyzers` function:

```python
def sync_cortex_analyzers(config_path: str = CONFIG_PATH) -> None:
    cfg: CronConfig = load_config(config_path)
    if not cfg.cortex:
        log_analyzers.error("Missing Cortex config")
        return

    api = Api(str(cfg.cortex.url), cfg.cortex.api_key)

    # Mount a timeout adapter on cortex4py's internal session
    _adapter = TimeoutHTTPAdapter()
    try:
        api._Api__session.mount("https://", _adapter)
        api._Api__session.mount("http://", _adapter)
    except AttributeError:
        log_analyzers.warning(
            "Could not mount TimeoutHTTPAdapter on cortex4py session — "
            "timeout not guaranteed for Cortex calls"
        )

    try:
        remote_analyzers = _fetch_all_analyzers(api)
    except pybreaker.CircuitBreakerError as exc:
        log_analyzers.warning("[breaker:cortex] open — sync_cortex_analyzers skipped: %s", exc)
        return
    except CortexException as exc:
        log_analyzers.error("Cortex fetch failed: %s", exc)
        return

    if not remote_analyzers:
        return

    remote_names = []
    with transaction.atomic():
        for analyzer in remote_analyzers:
            Analyzer.objects.update_or_create(
                name=analyzer.name,
                defaults={"analyzer_cortex_id": analyzer.id, "is_active": True},
            )
            remote_names.append(analyzer.name)
        Analyzer.objects.exclude(name__in=remote_names).update(is_active=False)
```

- [ ] **Step 4: Run existing tests**

```bash
cd Suspicious && python manage.py test tasp -v 2
```

Expected: `OK` (or same results as before)

- [ ] **Step 5: Run all new tests together**

```bash
cd Suspicious && python manage.py test common.tests score_process.score_utils.thehive.tests -v 2
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add Suspicious/Suspicious/tasp/cron/sync_cortex.py
git commit -m "feat(r3+p6): mount timeout adapter and add retry/breaker to Cortex analyzer sync"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| `timeout=(5, 30)` on all outbound calls | Tasks 2, 4, 5, 6 |
| `tenacity` retry (3×, exponential backoff) | Task 3 (RETRY), Tasks 4–6 (applied) |
| `pybreaker` circuit breaker per integration | Task 3 (BREAKERS), Tasks 4–6 (applied) |
| `phishing.py` 9 bare `requests.*` replaced | Task 4, Steps 5–9 |
| Cortex SDK session timeout | Tasks 5–6 (adapter mount) |
| `get_job_from_api` / `get_report_from_api` wrapped | Task 5, Steps 4–5 |
| `sync_cortex_analyzers` wrapped | Task 6 |
| `requirements.txt` updated | Task 1 |
| Unit tests: adapter, session, breakers, retry | Tasks 2–3 |
| Unit tests: phishing.py functions | Task 4 |
| `watcher.py`, `thehive_utils.py`, `oidc.py` not touched | ✓ (already correct) |

**No placeholders found.**
**Type consistency:** `_thehive_request` defined Task 4 Step 4, used Task 4 Steps 5–9. `_fetch_job`/`_fetch_report` defined Task 5 Step 3, used Task 5 Steps 4–5. `_fetch_all_analyzers` defined Task 6 Step 2, used Task 6 Step 3.
**Scope:** Focused on R3+P6. No unrelated changes.
