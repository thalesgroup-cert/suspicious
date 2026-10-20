# Allow-lists, campaign domains and MISP: launch, push and scoring rules

Status: APPROVED 2026-10-20 (weighted vote, strict majority); not implemented yet. Origin: user requests of 2026-10-20.

## 1. What each list means (user decisions)

| List | Meaning | Verdict | Cortex jobs | MISP |
|---|---|---|---|---|
| Allow lists (domains, IPs, file hashes, filetypes) | Known good | **Safe**, score 0, confidence 100, level `SAFE-ALLOW_LISTED`, with a visible "whitelisted" reason | Not launched | Never pushed |
| `campaign_domains_allow` | Authorised phishing simulations (internal or external tests) | **Dangerous** (kept in the deny set at scoring; this is intended) | Launched as today | **Never pushed** |
| Deny list, Watcher monitored | Known bad | Dangerous | Not launched (today) | Pushed |

## 2. Current gaps found (code read, 2026-10-20)

- IPs: no allow-list check before a job is launched (`artifacts.py:127`, `case_handler.py:155`). The check only happens inside the analyzer parser (`cortex_analyzers/base.py:52`), after the job ran.
- MISP (`connectors/contrib/misp/service.py`): domains are filtered (allow list, Watcher legit, company domains, subdomains included). URLs are filtered only for company domains, so a URL on an allow-listed domain is pushed. IPs and hashes are not filtered. Campaign domains are not filtered at all.
- Job launch matches domains exactly (no subdomains); MISP matches subdomains.

## 3. Changes

### 3.1 Job launch
- Skip IPs that are on `AllowListIp` (normalised compare through `ipaddress`), marking them `SAFE-ALLOW_LISTED` with the reason, in both the email path and the web submit path.
- Keep exact domain matching at launch. No subdomain widening: allow-listing `google.com` must not silence `sites.google.com`, and `blob.core.windows.net` style hosting must stay analysed.
- Precedence: deny list, Watcher monitored and campaign domains are never overridden by an allow-list entry.

### 3.2 MISP
- Skip: domain, URL host (through `url_host`, so `corp.example@evil.test` is `evil.test`) and address objects on campaign domains; URLs on allow-listed domains; hashes on `AllowListFile`; IPs on `AllowListIp`.
- Domains keep the existing subdomain rule.
- Per-IOC only. A case whose sender is a campaign domain is not skipped as a whole, so a real attacker spoofing a simulation sender still has the rest of its IOCs shared.

### 3.3 Scoring: allow-list is a vote, not an absolute override
User rule: if the AI classifier says Dangerous but the other analyzers and the whitelist say Safe, the result is Safe, and only when safe and whitelist signals are a majority.

Today `score_case` (`scoring/engine.py:109`) takes `base_score = max(worst, wmean)`, so one strong signal (the AI) wins over any number of safe ones, and whitelisted signals (confidence 100) also stop the AI from being decisive (`ai.confidence > base_conf` is false at 100).

Proposed rule, applied only when the case has at least one whitelisted signal (cases without are unchanged):
- Count signals by weight (the analyzer weights from the Scoring settings). A whitelisted signal counts with the weight of the analyzer it replaced.
- If safe plus whitelisted weight is **strictly more than half** of the scored weight, the verdict is Safe, score 0, confidence 100, rule `allow-list-majority`, and the reason names the dissenting analyzers ("Dangerous: AIMailAnalyzer").
- Otherwise the case is scored as today and the reason says it was not overridden ("allow-listed, but only 38% of weight agrees").
- Failed or pending analyzers are not counted.

False-positive guard: the dissent is always recorded in the verdict and shown in the case, so a Safe verdict built on a majority over a Dangerous AI is visible to analysts, and the dissent is part of the narration input.

## 4. UI / docs
- Settings: `campaign_domains_allow` purpose line: "Authorised phishing simulations: still scored Dangerous, never shared to MISP."
- Docs: `docs/operations/` allow-list page and the connectors MISP page.

## 5. Tests (Review Focus)
- IP on allow list: no job, `SAFE-ALLOW_LISTED`, reason set; IPv6 compressed/expanded forms match; an IP not on the list still launches.
- Lookalikes: `allowlisted.com.evil.tld`, `evil-allowlisted.com`, `sub.allowlisted.com` (no launch skip), `corp.example@evil.test` URL authority.
- Precedence: a domain on both allow and deny stays Dangerous; campaign domain stays Dangerous and is not pushed to MISP.
- MISP: each skipped type, and a domain that is not listed is still pushed.
- Majority: AI Dangerous with 3 safe plus a whitelist → Safe (rule, reason names the dissenter); exactly half → not overridden; AI Dangerous with 1 safe plus a whitelist where weights make safe < half → Dangerous; no whitelist signals → identical to today (golden cases).

## 6. Open points
- Decided: weighted, consistent with the Scoring panel.
- Decided: exactly half does not override (strict majority).
