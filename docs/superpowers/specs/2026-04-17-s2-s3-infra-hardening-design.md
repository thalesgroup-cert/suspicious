# S2 + S3 — Infra Hardening Design
**Date:** 2026-04-17
**Scope:** Disable Traefik dashboard (S2); add SSRF protection on URL submission (S3)
**Reviewer:** Claude Code (claude-sonnet-4-6) + TheoBhang

---

## Context

Two independent security findings from the architecture review:

- **S2** (`🔴 High`): `api.insecure: true` in `traefik/traefik.yaml` exposes the unauthenticated Traefik dashboard on port 8080 to every container on `suspicious_network`. The dashboard reveals routing rules, middleware config, and certificate metadata.
- **S3** (`🔴 High`): User-supplied URLs are forwarded to Cortex with no denylist for RFC-1918 ranges, `169.254.169.254` (cloud metadata), or loopback addresses. A user can submit `http://169.254.169.254/latest/meta-data/` and Cortex will fetch it.

---

## S2 — Disable Traefik Dashboard

### What Changes

**`traefik/traefik.yaml`** — one field change:

```yaml
# Before
api:
  dashboard: true
  insecure: true

# After
api:
  dashboard: false
```

Setting `dashboard: false` disables the dashboard UI entirely; Traefik ignores `insecure` when the dashboard is off. The port 8080 listener never starts.

### What Does NOT Change

- `compose_reverse_proxy.yaml` — the `8080` port mapping is already commented out; no change needed.
- All routing, middleware, TLS, and entrypoint config — untouched.

### Testing

Manual: `docker exec traefik wget -qO- http://localhost:8080/api/rawdata 2>&1` should return a connection refused error after the change.

---

## S3 — SSRF Protection on URL Submission

### Approach

Phase 1 (this spec): **parse-only** validation. Extract the hostname from the submitted URL. If the hostname is an IP address literal, reject it if it falls within any blocked range. Domain names pass through — DNS-resolution-time checks are deferred to phase 2.

Phase 2 (future): resolve the hostname via `socket.getaddrinfo` and apply the same blocked-range check. Requires a timeout/fallback strategy to avoid slowing submissions.

### Blocked Ranges

Using Python's `ipaddress` stdlib. An IP address is rejected if any of the following properties is `True`:

| Property | Example addresses blocked |
|---|---|
| `is_loopback` | `127.0.0.1`, `::1` |
| `is_private` | `10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`, `fc00::/7` |
| `is_link_local` | `169.254.x.x` (AWS/GCP metadata), `fe80::/10` |
| `is_multicast` | `224.0.0.0/4`, `ff00::/8` |
| `is_reserved` | `0.0.0.0/8`, `240.0.0.0/4`, and other IANA reserved blocks |
| `is_unspecified` | `0.0.0.0`, `::` |

### Implementation

**File:** `Suspicious/Suspicious/api/serializers/submit.py`

Add a module-level helper (private, one callsite):

```python
import ipaddress
from urllib.parse import urlparse

def _check_no_ssrf_ip(url: str) -> None:
    """
    Reject URLs whose hostname is a private/reserved IP address literal.
    Domain names are not resolved here (phase-2 work).
    Raises serializers.ValidationError on blocked addresses.
    """
    from rest_framework import serializers as _s

    hostname = urlparse(url).hostname  # None-safe; strips [] from IPv6 literals
    if not hostname:
        return  # URLField already validates non-empty URLs; nothing to check

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
        raise _s.ValidationError("URL targets a private or reserved address.")
```

Call it at the tail of `SubmitUrlSerializer.validate_url()`:

```python
def validate_url(self, value: str) -> str:
    value = value.strip()
    if value and not value.startswith(("http://", "https://")):
        value = f"http://{value}"
    _check_no_ssrf_ip(value)
    return value
```

The error message is intentionally vague — does not reveal internal topology.

### Testing

**New file:** `Suspicious/Suspicious/api/tests/test_ssrf.py`

Tested via `unittest` with the existing module-level stub pattern (no Django runner needed).

Test cases:

| Input URL | Expected outcome |
|---|---|
| `http://127.0.0.1/` | ValidationError |
| `http://10.0.0.1/path` | ValidationError |
| `http://172.16.0.1/` | ValidationError |
| `http://192.168.1.1/` | ValidationError |
| `http://169.254.169.254/latest/meta-data/` | ValidationError |
| `http://[::1]/` | ValidationError |
| `http://[fc00::1]/` | ValidationError |
| `http://0.0.0.0/` | ValidationError |
| `http://example.com/` | Passes (domain name) |
| `https://suspicious.corp.thales/api/` | Passes (domain name) |
| `http://8.8.8.8/` | Passes (public IP) |

---

## File Map

| Action | Path | Change |
|---|---|---|
| Modify | `traefik/traefik.yaml` | `dashboard: false`, remove `insecure: true` |
| Modify | `Suspicious/Suspicious/api/serializers/submit.py` | Add `_check_no_ssrf_ip()`, call from `validate_url` |
| Create | `Suspicious/Suspicious/api/tests/test_ssrf.py` | Unit tests for SSRF validation |

---

## Decision Log

| Decision | Choice | Reason |
|---|---|---|
| Dashboard | Disabled entirely | Not used in production; simplest, no auth config needed |
| SSRF scope | Parse-only (phase 1) | Safe first step; DNS resolution adds latency and failure modes |
| SSRF placement | Serializer `validate_url` | Earliest possible rejection; same file as URL normalization |
| Error message | Vague | Avoid topology disclosure to untrusted users |
| New file for helper | No — stays in `submit.py` | Single callsite; YAGNI |
