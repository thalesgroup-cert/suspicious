Submit URLs, IPs, domains, hashes, files and emails to Suspicious from a playbook, wait for the verdict, and enrich indicators with what Suspicious already knows.
This integration was integrated and tested with version xx of Suspicious.

## Configure Suspicious in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of your Suspicious instance, for example https://suspicious.example.com. | True |
| API token | A Suspicious API key. Create it in the Django admin under Profiles, API Keys, for the account this integration runs as. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Submit unknown indicators from reputation commands | When the url, ip, domain or file command finds no verdict on file, submit the value to Suspicious for analysis. Off by default, because an enrichment of many indicators then creates many cases. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### suspicious-submit-url

***
Submits a URL for analysis. With polling on, waits for the verdict.

#### Base Command

`suspicious-submit-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to analyse. Defanged forms (hxxp, [.]) are accepted. | Required | 
| context | Free-text note shown on the case, for example the ticket that triggered the submission. | Optional | 
| external_ref | Your reference for this submission. Submitting the same reference again returns the original case. Defaults to a value derived from the incident and the URL. | Optional | 
| force_new | Skip the automatic reference so the URL is analysed again, even inside the same incident. Possible values are: true, false. Default is false. | Optional | 
| polling | Wait for the verdict using the built-in polling. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Submission.case_id | Number | Id of the case Suspicious created, or of the earlier case it returned. | 
| Suspicious.Submission.external_ref | String | The reference stored with the case. | 
| Suspicious.Submission.reused | Boolean | True when an earlier case with the same external_ref was returned. | 
| Suspicious.Verdict.case_id | Number | Case id. | 
| Suspicious.Verdict.done | Boolean | True once the verdict is final. | 
| Suspicious.Verdict.result | String | Case verdict \(SAFE, INCONCLUSIVE, SUSPICIOUS, DANGEROUS, ALLOW_LISTED, FAILURE\). | 
| Suspicious.Verdict.dbot_score | Number | The verdict as a DBot score \(0 unknown, 1 good, 2 suspicious, 3 bad\). | 
| Suspicious.Verdict.score | Number | Aggregated risk score. | 
| Suspicious.Verdict.confidence | Number | Confidence of the verdict. | 
| Suspicious.Verdict.ai_classification | String | Threat category assigned by the classifier. | 
| Suspicious.Verdict.analysis_health.failed | Number | Number of analyzers that failed. A non-zero value lowers confidence in the verdict. | 
| Suspicious.Verdict.observables | Unknown | Per-observable verdicts of the case. | 
| DBotScore.Indicator | String | The indicator that was scored. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

### suspicious-submit-other

***
Submits an IP address or a file hash for analysis. With polling on, waits for the verdict.

#### Base Command

`suspicious-submit-other`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | An IP address or an MD5, SHA-1 or SHA-256 hash. | Required | 
| context | Free-text note shown on the case. | Optional | 
| external_ref | Your reference for this submission. Submitting the same reference again returns the original case. Defaults to a value derived from the incident and the value. | Optional | 
| force_new | Skip the automatic reference so the value is analysed again, even inside the same incident. Possible values are: true, false. Default is false. | Optional | 
| polling | Wait for the verdict using the built-in polling. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Submission.case_id | Number | Id of the case Suspicious created, or of the earlier case it returned. | 
| Suspicious.Verdict.case_id | Number | Case id. | 
| Suspicious.Verdict.done | Boolean | True once the verdict is final. | 
| Suspicious.Verdict.result | String | Case verdict. | 
| Suspicious.Verdict.dbot_score | Number | The verdict as a DBot score \(0 unknown, 1 good, 2 suspicious, 3 bad\). | 

### suspicious-submit-indicators

***
Submits a list of URLs, IPs, domains and hashes as one case, with a verdict per indicator. With polling on, waits for the verdict.

#### Base Command

`suspicious-submit-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | Indicators separated by commas, spaces or new lines. At most 100. | Required | 
| context | Free-text note shown on the case. | Optional | 
| external_ref | Your reference for this submission. Submitting the same reference again returns the original case. Defaults to a value derived from the incident and the list. | Optional | 
| force_new | Skip the automatic reference so the list is analysed again, even inside the same incident. Possible values are: true, false. Default is false. | Optional | 
| polling | Wait for the verdict using the built-in polling. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Submission.case_id | Number | Id of the case Suspicious created, or of the earlier case it returned. | 
| Suspicious.Submission.observable_count | Number | Number of indicators accepted. | 
| Suspicious.Submission.skipped | Unknown | Lines that were not valid indicators. | 
| Suspicious.Verdict.case_id | Number | Case id. | 
| Suspicious.Verdict.done | Boolean | True once the verdict is final. | 
| Suspicious.Verdict.result | String | Case verdict. | 
| Suspicious.Verdict.dbot_score | Number | The verdict as a DBot score \(0 unknown, 1 good, 2 suspicious, 3 bad\). | 
| Suspicious.Verdict.observables | Unknown | Per-observable verdicts of the case. | 

### suspicious-submit-file

***
Submits a file or an email (.eml, .msg) from the War Room for analysis. With polling on, waits for the verdict.

#### Base Command

`suspicious-submit-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | War Room entry id of the file. For a phishing report, the original .eml. | Required | 
| file_name | Name to give the file. Defaults to the name in the War Room. | Optional | 
| context | Free-text note shown on the case. | Optional | 
| external_ref | Your reference for this submission. Submitting the same reference again returns the original case. Defaults to a value derived from the incident and the file content. | Optional | 
| force_new | Skip the automatic reference so the file is analysed again, even inside the same incident. Possible values are: true, false. Default is false. | Optional | 
| polling | Wait for the verdict using the built-in polling. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Submission.case_id | Number | Id of the case Suspicious created, or of the earlier case it returned. | 
| Suspicious.Verdict.case_id | Number | Case id. | 
| Suspicious.Verdict.done | Boolean | True once the verdict is final. | 
| Suspicious.Verdict.result | String | Case verdict. | 
| Suspicious.Verdict.dbot_score | Number | The verdict as a DBot score \(0 unknown, 1 good, 2 suspicious, 3 bad\). | 
| Suspicious.Verdict.observables | Unknown | Per-observable verdicts of the case \(URLs, IPs, domains and hashes found in an email\). | 

### suspicious-get-verdict

***
Gets the status and, once final, the verdict of a case. With polling on, waits until it is final.

#### Base Command

`suspicious-get-verdict`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Id of the case, from a submit command. | Required | 
| polling | Wait for the verdict using the built-in polling. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Verdict.case_id | Number | Case id. | 
| Suspicious.Verdict.status | String | Case status \(NEW, IN_PROGRESS, DONE, CHALLENGED\). | 
| Suspicious.Verdict.done | Boolean | True once the verdict is final. | 
| Suspicious.Verdict.result | String | Case verdict. Empty until done. | 
| Suspicious.Verdict.dbot_score | Number | The verdict as a DBot score \(0 unknown, 1 good, 2 suspicious, 3 bad\). Set once done. | 
| Suspicious.Verdict.score | Number | Aggregated risk score. | 
| Suspicious.Verdict.confidence | Number | Confidence of the verdict. | 
| Suspicious.Verdict.external_ref | String | The reference stored with the case. | 
| Suspicious.Verdict.observables | Unknown | Per-observable verdicts of the case. | 

### suspicious-get-ticket

***
Gets the ticket-ready payload of a case (verdict, rationale, observables, recommended action). Needs an investigator account.

#### Base Command

`suspicious-get-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Id of the case. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Ticket.case_id | Number | Case id. | 
| Suspicious.Ticket.title | String | Suggested ticket title. | 
| Suspicious.Ticket.verdict | Unknown | Verdict, score, severity and rationale. | 
| Suspicious.Ticket.observables | Unknown | Observables with their verdict. | 
| Suspicious.Ticket.recommended_action | String | What Suspicious recommends doing about the verdict. | 

### suspicious-get-report

***
Downloads the case report as a file.

#### Base Command

`suspicious-get-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Id of the case. | Required | 
| format | Report format. Possible values are: markdown, html. Default is markdown. | Optional | 

#### Context Output

There is no context output for this command.
### suspicious-challenge

***
Challenges the verdict of a case. An analyst reviews the proposed verdict. Only the account that submitted the case can challenge it.

#### Base Command

`suspicious-challenge`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Id of the case. | Required | 
| proposed_result | The verdict you believe is right. Possible values are: Safe, Dangerous. | Required | 
| reason | Why the verdict is wrong. | Optional | 

#### Context Output

There is no context output for this command.
### url

***
Returns the verdict Suspicious already holds for URLs. Needs an investigator account.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URLs to look up. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Lookup.value | String | The value that was looked up. | 
| Suspicious.Lookup.known | Boolean | True when Suspicious holds a verdict. | 
| Suspicious.Lookup.verdict | String | malicious, suspicious, safe or inconclusive. | 
| Suspicious.Lookup.score | Number | Risk score of the observable. | 
| URL.Data | String | The URL. | 
| DBotScore.Indicator | String | The indicator that was scored. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

### ip

***
Returns the verdict Suspicious already holds for IP addresses. Needs an investigator account.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP addresses to look up. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Lookup.value | String | The value that was looked up. | 
| Suspicious.Lookup.known | Boolean | True when Suspicious holds a verdict. | 
| Suspicious.Lookup.verdict | String | malicious, suspicious, safe or inconclusive. | 
| Suspicious.Lookup.score | Number | Risk score of the observable. | 
| IP.Address | String | The IP address. | 
| DBotScore.Indicator | String | The indicator that was scored. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

### domain

***
Returns the verdict Suspicious already holds for domains. Needs an investigator account.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domains to look up. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Lookup.value | String | The value that was looked up. | 
| Suspicious.Lookup.known | Boolean | True when Suspicious holds a verdict. | 
| Suspicious.Lookup.verdict | String | malicious, suspicious, safe or inconclusive. | 
| Suspicious.Lookup.score | Number | Risk score of the observable. | 
| Domain.Name | String | The domain. | 
| DBotScore.Indicator | String | The indicator that was scored. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

### file

***
Returns the verdict Suspicious already holds for file hashes (MD5, SHA-1, SHA-256). Needs an investigator account.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hashes to look up. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Suspicious.Lookup.value | String | The value that was looked up. | 
| Suspicious.Lookup.known | Boolean | True when Suspicious holds a verdict. | 
| Suspicious.Lookup.verdict | String | malicious, suspicious, safe or inconclusive. | 
| Suspicious.Lookup.score | Number | Risk score of the observable. | 
| File.MD5 | String | The MD5 hash. | 
| File.SHA1 | String | The SHA-1 hash. | 
| File.SHA256 | String | The SHA-256 hash. | 
| DBotScore.Indicator | String | The indicator that was scored. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
