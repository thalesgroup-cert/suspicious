# Campaign detection as a core service, TheHive as a consumer

## Problem
Phishing-campaign detection and the TheHive push run as side effects inside the
AI analyzer's *parser* (`ai_mail.py:_run_campaign`). A parser runs on every
scoring pass, with or without a case, so the work is repeated, racy, unretried
and invisible when it fails (no ledger, no on/off switch). A campaign exists
only as ChromaDB metadata plus a TheHive alert id; resetting TheHive orphaned
every stored id.

## Design
1. **`Campaign` + `CampaignMember` models** (case_handler). A campaign has a
   stable `ref`, a title, and `external_refs` (e.g. `{"thehive": "~123"}`). A
   case belongs to at most one campaign. Each member records which connectors
   already received it (`synced`).
2. **Detection service** (`case_handler/campaigns.py`) runs once per case at
   finalisation, right after `case_finalised`. It keeps today's rules (AI
   malscore above 6.5, sender domain not allow-listed, at least 3 similar
   dangerous mails within distance 0.25) but under one cache lock, with
   membership stored in the database. Each mail is one ChromaDB document
   (`case-<id>`); the campaign `ref` is written to its `sourceRefs` so the
   Campaigns page keeps grouping mails.
3. **`campaign_updated` event** through the connector framework; the payload is
   the usual case snapshot plus an optional `campaign_id`.
4. **TheHive connector** subscribes. It creates the alert in one multipart call
   (alert, observables, relevant files as file observables), or updates the
   existing one with the new members. Retries, ledger, health and
   `redeliver_connector` come from the framework. A missing alert is recreated.
5. **Content** (connector package): relevant attachments only (no empty files,
   no tracking pixels, size-capped, de-duplicated by sha256), IOCs from headers,
   both bodies and attachments (URLs, domains, IPs, senders, hashes, file
   names), a structured description, severity from verdict and campaign size,
   TLP/PAP amber.
6. The AI parser goes back to pure scoring.

## Out of scope
UI changes, campaign merging, other connectors consuming `campaign_updated`.
