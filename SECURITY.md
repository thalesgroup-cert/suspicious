# Security Policy

Suspicious is an AI-powered phishing and threat-analysis platform maintained by
**Thales Group CERT**. It ingests and detonates untrusted, often malicious
content (emails, files, URLs, IPs, hashes) by design, so its security posture is
central to how it is built and operated.

## Reporting a Vulnerability

Please report potential security issues to the **Thales Product Security
Incident Response Team (PSIRT)**:

* **Email:** `psirt(at)thalesgroup[.]com`
* **PGP (recommended for sensitive details):** Thales PSIRT PGP Key
  * **ID:** `0x8448AE39`
  * **Fingerprint:** `FC3C 4520 576E C756 AE73 0030 5369 49C4 8448 AE39`

Encrypt any report that contains sensitive information (proof-of-concept,
affected customer data, exploit details) with the PGP key above.

To notify Thales about a cybersecurity incident involving Thales
infrastructure (as opposed to a vulnerability in this software), refer to the
Thales CERT page instead.

Please do **not** open a public GitHub issue for security reports, and do not
include exploit details in pull requests. Sales or prospection emails sent to
the PSIRT address are ignored.

## Responsible Disclosure

Thales follows a Responsible Disclosure model. Reported issues are qualified and
impact-assessed; once a report is confirmed, the reporter is informed of the
investigation and an **embargo period is agreed** so risks to customers and end
users can be mitigated before any public disclosure.

By submitting a report, each reporter commits to the following:

* Do not take advantage of the security issue — for example, do not download
  more data than necessary to demonstrate the vulnerability, and do not
  delete or modify data.
* Do not disclose the issue until it has been resolved and without Thales's
  consent.
* Do not perform attacks such as social engineering, denial of service,
  physical site intrusion, spam, or attacks against third-party applications.

Please be thoughtful about the time and attention a report requires. Repeated
failure to respect this policy may result in future reports being declined.

## Supported Versions

Security fixes are provided for the **latest released version** and the current
`main` branch. Older versions are addressed on a best-effort basis only. Always
reproduce against the latest release before reporting.

## Threat Model

Our threat model makes the following assumptions. A reported issue that requires
breaking one of these assumptions will be treated as a regular bug or a
non-issue rather than a security vulnerability.

* **Transport is protected.** TLS/HTTPS connections (UI, API, Cortex webhook,
  IMAP/SMTP, LDAP/OIDC, S3) are terminated and verified as configured and are
  not intercepted or tampered with. Deployments that disable certificate
  verification (e.g. `verify_ssl=false`) accept the corresponding MITM risk
  intentionally.
* **Secrets are protected.** Secrets are held in HashiCorp Vault (or, in
  dev/CI, the `settings.json` fallback). The Vault server, its unseal keys, the
  AppRole credentials in `.env`, and the host filesystem are trusted and not
  compromised. `.env` and the operator's real `settings.json` are kept out of
  version control.
* **Configuration is intentional.** All runtime configuration — environment
  variables, `settings.json`, database-backed `RuntimeConfig`, and Django
  settings such as `DEBUG`, `ALLOWED_HOSTS`, and cookie flags — is set
  deliberately by the operator. Running with development settings in production
  is an operator error, not a vulnerability in the platform.
* **The operator host and orchestration are trusted.** The Docker host, the
  container runtime, the reverse proxy (Traefik), and the internal Compose
  network are administered by trusted operators. An attacker with host, root,
  or Docker-socket access is out of scope.
* **Privileged platform roles are trusted.** Users granted Admin or CERT roles
  are trusted to administer the platform (edit connectors, secrets via the
  Settings UI, blacklists/whitelists, etc.). Abuse by an authorized privileged
  user is not a vulnerability.
* **Analysis of hostile content is the product's purpose.** Suspicious parses
  and detonates attacker-supplied emails, files, and URLs through Cortex
  analyzers, YARA, the ML classifier, and sandboxing. The execution and
  classification of malicious samples inside the intended analyzer isolation is
  by design; a sample being malicious is not itself a vulnerability.
* **Third-party services are trusted within their boundary.** Integrations
  (Cortex, TheHive, MISP, Elasticsearch, ChromaDB, the IMAP/SMTP servers, the
  identity provider) behave according to their own contracts and are
  administered separately. Vulnerabilities in those products should be reported
  to their respective maintainers.

### In scope

Subject to the assumptions above, we consider the following security-relevant:

* Authentication or session bypass, and privilege escalation between
  unauthenticated / authenticated / Admin / CERT levels.
* Insecure direct object access (IDOR) to cases, reports, or artifacts
  belonging to other users or scopes.
* Forgery or replay of the Cortex result webhook (HMAC signature bypass, jobId
  de-duplication bypass, or `case_id ↔ cortex_job_id` confusion).
* Server-side request forgery (SSRF) reachable through URL / IP / domain
  submission and analysis that is not already an accepted property of analyzing
  attacker-controlled observables.
* Injection (SQL, command, template, LDAP), unsafe deserialization, and
  stored/reflected XSS in the React UI or Django responses.
* Leakage of secrets (API keys, passwords, the Django secret key) into logs,
  API responses, or the UI — including secret values echoed back instead of the
  mask.
* Sandbox or analyzer escape that yields code execution on the platform itself
  rather than within the intended analyzer isolation.

### Out of scope

* Anything requiring a broken assumption from the list above (compromised
  Vault/host, intercepted TLS, intentional insecure configuration, abuse by a
  trusted privileged user).
* Denial of service, traffic flooding, and resource-exhaustion reports.
* Findings from automated scanners without a demonstrated, realistic impact.
* Self-XSS, missing security headers, or best-practice suggestions with no
  concrete exploit, absent a working proof of concept.
* Vulnerabilities in third-party dependencies or integrated products that are
  not exploitable through Suspicious as configured by default.
