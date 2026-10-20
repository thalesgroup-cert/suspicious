## Suspicious

Connects Cortex XSOAR to your Suspicious instance.

1. In Suspicious, open the Django admin, then **Profiles → API Keys → Add**. Pick the account this integration should run as and an expiry. Copy the token: it is shown once.
2. Enter your Suspicious URL and the token here, then click **Test**.

**Which account?** A normal account can submit and read back its own cases (`suspicious-submit-*`, `suspicious-get-verdict`, `suspicious-get-report`, `suspicious-challenge`). The `url`, `ip`, `domain` and `file` reputation commands and `suspicious-get-ticket` need an **investigator** account (member of the CERT, CISO or Admin group). Use one account per automation so its activity stays visible and its key can be revoked on its own.
