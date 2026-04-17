# S2 + S3 — Infra Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Disable the unauthenticated Traefik dashboard (S2) and block SSRF attacks via private/reserved IP literals in URL submissions (S3).

**Architecture:** S2 is a single config-file change. S3 adds a pure-stdlib helper `_check_no_ssrf_ip()` to `api/serializers/submit.py` that raises `ValueError` for blocked IPs; the serializer's `validate_url` converts it to a DRF `ValidationError`. No new files needed.

**Tech Stack:** Python `ipaddress` + `urllib.parse` (stdlib); Traefik static config YAML; Django REST Framework serializer validation.

**Spec:** `docs/superpowers/specs/2026-04-17-s2-s3-infra-hardening-design.md`

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Modify | `traefik/traefik.yaml` | Disable Traefik dashboard |
| Modify | `Suspicious/Suspicious/api/serializers/submit.py` | Add `_check_no_ssrf_ip()`, wire into `validate_url` |
| Create | `Suspicious/Suspicious/api/tests/test_ssrf.py` | Unit tests for SSRF helper |

---

## Task 1: Disable Traefik Dashboard (S2)

**Files:**
- Modify: `traefik/traefik.yaml`

- [ ] **Step 1: Edit `traefik/traefik.yaml`**

Open `traefik/traefik.yaml`. Replace:

```yaml
api:
  dashboard: true
  insecure: true
```

With:

```yaml
api:
  dashboard: false
```

The full file after the change:

```yaml
log:
  level: DEBUG
  filePath: "/var/log/traefik/traefik.log"

accessLog:
  filePath: "/var/log/traefik/access.log"
  bufferingSize: 100

entryPoints:
  websecure:
    address: ":443"
    http:
      tls:
        options: default

api:
  dashboard: false

providers:
  file:
    directory: /dynamic
    watch: true

tls:
  stores:
    default:
      defaultCertificate:
        certFile: /etc/private/certfile.pem
        keyFile:  /etc/private/keyfile.pem
  options:
    default:
      minVersion: VersionTLS12
      clientAuth:
        caFiles:
          - /etc/private/rootcafile.pem
        clientAuthType: VerifyIfGiven
```

- [ ] **Step 2: Verify the YAML is valid**

```bash
python3 -c "import yaml; yaml.safe_load(open('traefik/traefik.yaml'))" && echo "OK"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add traefik/traefik.yaml
git commit -m "fix(traefik): disable dashboard (S2 — api.insecure removed)"
```

---

## Task 2: SSRF Protection on URL Submission (S3)

**Files:**
- Create: `Suspicious/Suspicious/api/tests/test_ssrf.py`
- Modify: `Suspicious/Suspicious/api/serializers/submit.py`

### Background

`api/serializers/submit.py` already imports `from django.conf import settings` and `from rest_framework import serializers` at the top. The test file stubs both before importing — same pattern as `api/tests/test_dashboard_cache.py`.

`_check_no_ssrf_ip(url)` raises `ValueError` (no DRF dependency). `validate_url` converts it to `serializers.ValidationError`.

- [ ] **Step 1: Write the failing tests**

Create `Suspicious/Suspicious/api/tests/test_ssrf.py`:

```python
"""
Unit tests for SSRF protection in SubmitUrlSerializer.

_check_no_ssrf_ip() is tested directly — it uses only stdlib so needs
no stubs of its own.  We stub django.conf and rest_framework so that
api.serializers.submit can be imported without a running Django process.
"""
import sys
import unittest
from unittest.mock import MagicMock


def _setup_stubs():
    conf_stub = MagicMock()
    conf_stub.settings = MagicMock()
    conf_stub.settings.SUBMIT_CONTEXT_MAX_LENGTH = 2000
    conf_stub.settings.SUBMIT_OTHER_MAX_LENGTH = 4096
    conf_stub.settings.SUBMIT_FILE_MAX_BYTES = 25 * 1024 * 1024

    class _FakeValidationError(Exception):
        def __init__(self, detail):
            self.detail = detail
            super().__init__(detail)

    drf_serializers_stub = MagicMock()
    drf_serializers_stub.ValidationError = _FakeValidationError
    drf_serializers_stub.Serializer = object
    drf_serializers_stub.CharField = MagicMock(return_value=MagicMock())
    drf_serializers_stub.URLField = MagicMock(return_value=MagicMock())
    drf_serializers_stub.FileField = MagicMock(return_value=MagicMock())
    drf_serializers_stub.EmailField = MagicMock(return_value=MagicMock())

    sys.modules.setdefault("django",                   MagicMock())
    sys.modules.setdefault("django.conf",              conf_stub)
    sys.modules.setdefault("rest_framework",           MagicMock())
    sys.modules.setdefault("rest_framework.serializers", drf_serializers_stub)


_setup_stubs()

# Force a fresh import of the module so our stubs take effect
for _k in list(sys.modules):
    if "api.serializers.submit" in _k:
        del sys.modules[_k]

from api.serializers.submit import _check_no_ssrf_ip  # noqa: E402


class TestCheckNoSsrfIp(unittest.TestCase):

    # ── Blocked: loopback ───────────────────────────────────────────────────

    def test_blocks_ipv4_loopback(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://127.0.0.1/")

    def test_blocks_ipv6_loopback(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://[::1]/")

    # ── Blocked: RFC-1918 private ranges ───────────────────────────────────

    def test_blocks_10_dot(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://10.0.0.1/path")

    def test_blocks_172_16(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://172.16.0.1/")

    def test_blocks_172_31(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://172.31.255.255/")

    def test_blocks_192_168(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://192.168.1.1/")

    # ── Blocked: link-local (AWS/GCP metadata endpoint) ────────────────────

    def test_blocks_aws_metadata(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://169.254.169.254/latest/meta-data/")

    def test_blocks_link_local_ipv6(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://[fe80::1]/")

    # ── Blocked: unique-local IPv6 ─────────────────────────────────────────

    def test_blocks_ipv6_unique_local(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://[fc00::1]/")

    # ── Blocked: unspecified ───────────────────────────────────────────────

    def test_blocks_unspecified_ipv4(self):
        with self.assertRaises(ValueError):
            _check_no_ssrf_ip("http://0.0.0.0/")

    # ── Allowed: public IPs ────────────────────────────────────────────────

    def test_allows_public_ip(self):
        # Should not raise
        _check_no_ssrf_ip("http://8.8.8.8/")

    def test_allows_public_ip_https(self):
        _check_no_ssrf_ip("https://1.1.1.1/")

    # ── Allowed: domain names (not resolved in phase 1) ───────────────────

    def test_allows_domain_name(self):
        _check_no_ssrf_ip("http://example.com/")

    def test_allows_internal_domain(self):
        # Domain names pass through — DNS resolution is phase 2
        _check_no_ssrf_ip("https://suspicious.corp.thales/api/")

    # ── Edge cases ─────────────────────────────────────────────────────────

    def test_empty_hostname_does_not_raise(self):
        # URLField already rejects these; helper should not crash
        _check_no_ssrf_ip("http:///path")

    def test_error_message_is_vague(self):
        try:
            _check_no_ssrf_ip("http://127.0.0.1/")
            self.fail("Expected ValueError")
        except ValueError as e:
            self.assertIn("private or reserved", str(e))
            # Must NOT reveal internal topology details
            self.assertNotIn("127.0.0.1", str(e))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd Suspicious/Suspicious
python -m unittest api.tests.test_ssrf -v 2>&1 | tail -10
```

Expected: `ImportError: cannot import name '_check_no_ssrf_ip' from 'api.serializers.submit'`

- [ ] **Step 3: Add `_check_no_ssrf_ip` to `api/serializers/submit.py`**

Open `Suspicious/Suspicious/api/serializers/submit.py`.

Add these two imports at the top of the file (after the existing imports):

```python
import ipaddress
from urllib.parse import urlparse
```

Then add the helper function immediately before the `SubmitUrlSerializer` class:

```python
def _check_no_ssrf_ip(url: str) -> None:
    """
    Reject URLs whose hostname is a private/reserved IP address literal.

    Raises ValueError for blocked addresses. Domain names are not resolved
    here — DNS-time checks are phase-2 work.

    Blocked: loopback, RFC-1918 private, link-local (169.254.x.x / fe80::),
             unique-local IPv6 (fc00::/7), multicast, reserved, unspecified.
    """
    hostname = urlparse(url).hostname  # strips [] from IPv6 literals; None-safe
    if not hostname:
        return

    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return  # hostname is a domain name — pass through

    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        raise ValueError("URL targets a private or reserved address.")
```

The full `api/serializers/submit.py` header section after the change:

```python
# api/serializers/submit.py
import ipaddress
from urllib.parse import urlparse

from django.conf import settings
from rest_framework import serializers


DEFAULT_CONTEXT_MAX_LENGTH = 2000
DEFAULT_OTHER_MAX_LENGTH = 4096
DEFAULT_UPLOAD_MAX_BYTES = 25 * 1024 * 1024  # 25 MB


def _check_no_ssrf_ip(url: str) -> None:
    """
    Reject URLs whose hostname is a private/reserved IP address literal.

    Raises ValueError for blocked addresses. Domain names are not resolved
    here — DNS-time checks are phase-2 work.

    Blocked: loopback, RFC-1918 private, link-local (169.254.x.x / fe80::),
             unique-local IPv6 (fc00::/7), multicast, reserved, unspecified.
    """
    hostname = urlparse(url).hostname  # strips [] from IPv6 literals; None-safe
    if not hostname:
        return

    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return  # hostname is a domain name — pass through

    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        raise ValueError("URL targets a private or reserved address.")
```

- [ ] **Step 4: Wire `_check_no_ssrf_ip` into `SubmitUrlSerializer.validate_url`**

In `Suspicious/Suspicious/api/serializers/submit.py`, replace the existing `validate_url` method:

```python
    def validate_url(self, value: str) -> str:
        value = value.strip()
        # Normalise bare domains that arrive without a scheme.
        # The frontend already prepends http:// for bare domains, but this
        # acts as a safety net in case the value slips through uncorrected.
        if value and not value.startswith(("http://", "https://")):
            value = f"http://{value}"
        return value
```

With:

```python
    def validate_url(self, value: str) -> str:
        value = value.strip()
        # Normalise bare domains that arrive without a scheme.
        # The frontend already prepends http:// for bare domains, but this
        # acts as a safety net in case the value slips through uncorrected.
        if value and not value.startswith(("http://", "https://")):
            value = f"http://{value}"
        try:
            _check_no_ssrf_ip(value)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc
        return value
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd Suspicious/Suspicious
python -m unittest api.tests.test_ssrf -v 2>&1 | tail -10
```

Expected:

```
----------------------------------------------------------------------
Ran 16 tests in 0.XXXs

OK
```

- [ ] **Step 6: Run all existing tests to check for regressions**

```bash
cd Suspicious/Suspicious
python -m unittest tasp.tests api.tests.test_dashboard_cache api.tests.test_ssrf 2>&1 | tail -5
```

Expected: `Ran 37 tests in 0.XXXs` `OK`

- [ ] **Step 7: Commit**

```bash
git add Suspicious/Suspicious/api/serializers/submit.py \
        Suspicious/Suspicious/api/tests/test_ssrf.py
git commit -m "feat(security): add SSRF IP-literal denylist on URL submission (S3)"
```
