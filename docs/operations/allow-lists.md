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

## MISP: what is not shared

The MISP connector withholds these indicators from shared events:

- Campaign (phishing-simulation) domains: domain objects, URL hosts and email-address objects. Subdomains are included.
- Domains and URLs whose host is on the domain allow list (subdomains included).
- Hashes on the file allow list.
- IPs on the IP allow list.

Filtering is per IOC: a case from a campaign sender still shares its other IOCs. MISP matching covers subdomains, while launch matching is on exact domains.

Hash skips compare the stored value of the allow-listed hash only: an md5 entry does not cover the same file's sha256 IOC.
