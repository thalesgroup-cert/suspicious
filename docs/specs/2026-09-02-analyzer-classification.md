# Analyzer classification — code-execution surface vs. egress surface

**Date:** 2026-09-02

Classifies the Cortex analyzers Suspicious dispatches by the isolation control
they actually need. The separate-service-vs-in-process split is *not* the
security boundary; what matters per analyzer is (a) does it execute
attacker-controlled code in-process, and (b) what outbound network does it need.

> **Note (2026-09-10):** this file was reconstructed at its planned path while
> implementing the URL-screenshot feature (Task 12) — the original draft lived
> outside the repo. Reconcile with any pre-existing copy before relying on the
> non-screenshot rows.

## Bucket ① — sandbox + `net=none`

The entire attacker-code-execution surface. All need zero outbound network, so
they are fully air-gappable. Isolation = bubblewrap/nsjail + seccomp +
`net=none` + read-only FS + rlimits, run as subprocesses (no Docker daemon).

- **FileInfo_8_0** — libmagic / parsers over the attacker file. Keep it
  keyless and network-free so it stays in this bucket.
- **Yara_Boosted_3_2** — Yara rules over attacker file / `mail_body`.
- **AI_Mail_Analyzer** — `tarfile.open` on the attacker archive + html2text /
  chardet on attacker HTML, then the phishing classifier. Higher risk than "just
  a venv".
- **Mail_Header_Analyzer** — header parse of attacker-supplied headers.

Return-path validation (schema-check `output.json` against the contract
fixtures before scoring consumes it) matters most for FileInfo + AI_Mail.

## Bucket ② — egress-allowlist, no sandbox

None execute attacker code. Each reaches a third-party service; most hold an API
key. Risk = key theft + exfiltration over the *allowed* egress (a sandbox does
not help). Controls = per-analyzer egress allowlist, scoped keys, rotation,
egress-volume alerting.

- ThreatGridOnPrem_1_0 — Cisco ThreatGrid sandbox. Also ships the raw sample
  offsite (a TLP / data-governance call, separate from code-exec).
- VirusTotal_GetReport — hash/URL/domain/IP reputation lookup. API key.
- Urlscan_io_Search — passive urlscan.io lookup. API key.
- Zscaler — URL category lookup. API key.
- MISP — indicator lookup against a MISP instance. API key.
- CIRCLHashlookup — known-file lookup. Keyless.
- GoogleDNS_resolve — DoH resolution. Keyless.
- All OSINT `ip`/`url`/`domain` type-dispatch analyzers enabled by
  `deployment/scripts/enable-dev-analyzers.sh`.
- **Lookyloo_Screenshot** — submits the URL to a Lookyloo instance, returns the
  rendered PNG. No attacker code in-process. Egress: the Lookyloo instance host
  (dev: `lookyloo.circl.lu`; prod: the private instance).
- **Urlscan.io_Scan** — submits the URL to urlscan.io, returns scan JSON + a
  screenshot URL. No attacker code in-process. Egress: `urlscan.io`. API key.

## Takeaway

The code-exec surface is 4 analyzers, all network-free, 3 of them Thales's own
code — the credential-isolated in-process worker recommendation is cleanly
implementable. Diff this table against `GET /api/analyzer` on the live Cortex
org before acting on it.
