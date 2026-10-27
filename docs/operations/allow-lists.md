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
- Domains and URLs whose host is exactly on the domain allow list (subdomains are not covered, so allow-listing `sharepoint.com` never hides `evil.sharepoint.com`). Company and Watcher legit domains keep the subdomain rule.
- Hashes on the file allow list.
- IPs on the IP allow list.

Filtering is per IOC: a case from a campaign sender still shares its other IOCs. Company, Watcher legit and campaign domains are matched with their subdomains; allow-listed domains are matched exactly, like launch.

Hash skips compare the stored value of the allow-listed hash only: an md5 entry does not cover the same file's sha256 IOC.

## Scoring: an allow-list is a vote

Allow-listing is not only a launch filter, it also takes part in the verdict:

- Each analyzer casts one weighted vote (its configured weight). Its band is the worst across all of its reports on the case, so a tool that flags one artifact and is allow-listed on another votes dissent, not safe. The AI analyzer votes from its signal.
- A vote is marked allow-listed when its band is Safe and at least one of its reports carries an allow-list marker that is still valid: the allow-list check is re-run for the report's target at scoring time, so a removed entry or a domain that is now deny-listed, Watcher-monitored or campaign no longer counts.
- When the Safe plus allow-listed weight is a strict majority of the voting weight, the case is Safe under the rule `allow-list-majority`, and the rationale names the dissenting analyzers.
- The majority can only overrule dissent that is about an allow-listed target. If any analyzer flagged something else (another link, domain, IP or file, the mail headers, or the AI classifier on the mail text), the case is not overridden and the rationale says which analyzer flagged it. Otherwise an attacker could add one allow-listed link to a phishing mail and let the Safe votes of analyzers that saw nothing outvote the one that did.

### Letting an allow-list overrule the AI for company mail

By default the AI classifier's finding on the mail text is never overruled by an allow-list. To let a legitimate company mail that the AI got wrong through, set `scoring.trusted_authserv_ids` to the authserv-ids of your own mail gateways (a JSON list such as `["mx.example.com"]`; in `settings.json` under `scoring`, or as a Runtime config row in the Django admin). It is empty by default, which keeps this off.

The AI's finding can then be overruled, through the usual majority, only when all of these hold for the reported mail:

- It has exactly one `From` address, on a company domain (own domains from the contact email, SMTP login and `email.content.global_domain`, plus Watcher legit domains, subdomains included).
- An `Authentication-Results` header whose authserv-id is in `scoring.trusted_authserv_ids` reports `dmarc=pass` (with `header.from` equal to the `From` domain when present). Results from any other authserv-id are ignored, because everything else in a forwarded mail can be written by the sender.
- Every URL, domain, IP and address in the mail is allow-listed (exact match) or on a company domain. A mail with an attachment never qualifies.

Any failure to read the stored headers or evaluate these conditions counts as "not satisfied". Your gateway must strip or replace `Authentication-Results` headers that arrive from outside under its own authserv-id, as RFC 8601 requires.
- Reports with no recheckable target (hash, mail address, mail body, mail header) never carry a marker, so they never vote as allow-listed.
- Reports that do not vote: failed or pending jobs, `info` level, confidence below the floor, and analyzers with weight 0.
- Deny-listed, campaign and Watcher-monitored targets are never overridden by the majority.
- The embedded-IOC escalation still applies afterwards.

What is guaranteed: launch normally skips allow-listed values, so a vote only becomes allow-listed for reports that exist anyway (a job that was already running, a list edited after the job ran, or an analyzer that runs at case level on an allow-listed target). The majority rule is therefore a safety net, not the main path. If building the votes fails, scoring falls back to the verdict without votes and the failure is logged.
