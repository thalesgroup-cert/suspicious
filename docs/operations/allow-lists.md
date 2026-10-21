# Allow lists

How the Settings lists change what Suspicious does with an observable. Manage the lists from Settings (see [Settings](../components/backend/settings.md)).

## What each list means

| List | Meaning | Verdict | Cortex jobs | MISP |
|---|---|---|---|---|
| Allow lists (domains, IPs, file hashes, file types) | Known good | Safe: score 0, confidence 100, level `SAFE-ALLOW_LISTED`, with a visible allow-listed reason | Not launched | Never pushed |
| Campaign domains (`campaign_domains_allow`) | Authorised phishing simulations, internal or external | Dangerous. This is intended: the simulation is still a phishing mail | Launched as usual | Never pushed |
| Deny list, Watcher monitored domains | Known bad | Dangerous | Not launched | Pushed |

## Job launch

An allow-listed observable gets its Safe verdict at submission time and no Cortex analyzer runs for it. This applies to submissions from the web form and to artifacts extracted from an ingested email.

- **IPs** are matched on the parsed address, so `2606:4700:4700:0:0:0:0:1111` and `2606:4700:4700::1111` are the same entry.
- **Domains** are matched exactly. Allow-listing `google.com` does not allow `sites.google.com`, `google.com.evil.tld` or `evil-google.com`. List the subdomain itself if you want it skipped.
- **Precedence**: an allow-list entry never beats a deny-listed domain, a Watcher monitored domain or a campaign domain. A domain on both an allow list and the deny list is marked dangerous and not analysed; a domain on both an allow list and the campaign list is analysed as usual.
