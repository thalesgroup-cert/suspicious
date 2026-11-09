# Mail Header Analyzer

`Analyzers/MailHeaderAnalyzer/` is a Cortex analyzer that gives a rule-based verdict
on a mail's headers. It does not read the body and does not use a model or the
network. Catalog name `Mail_Header_Analyzer`, version `1.0`
(`MailHeaderAnalyzer.json`, also listed in `Analyzers/analyzers.json`).

## Input

| Data type | What it accepts |
|---|---|
| `mail_header` | A raw header block. Headers that were flattened onto one line are reflowed before parsing |
| `file` | A `.eml` file (the `filename` parameter must end in `.eml`); only its headers are read |

Anything else, an empty header block or an unreadable `.eml` ends the job with an
error.

## Checks

| Predicate | Rule | Level |
|---|---|---|
| `SPF`, `DKIM`, `DMARC` | Read from every `Authentication-Results` header. A mechanism is `pass` only if each occurrence passed; otherwise the first non-pass result is reported; `none` if it never appeared | `pass` safe, `none` info, anything else suspicious |
| `ReplyToMatch` | Domain of `Reply-To` against the domain of `From` | absent info, match safe, mismatch suspicious (value `from != other`) |
| `ReturnPathMatch` | The same comparison for `Return-Path` | as above |
| `DisplayNameSpoofing` | The `From` display name embeds an address whose domain differs from the real `From` domain | spoofing malicious (value lists the embedded addresses), otherwise safe |

Addresses defanged with `[.]` or `(.)` are restored before the domain is compared.

The report carries the raw signals (`auth_results`, `reply_to`, `return_path`,
`display_name_spoofing`) and `taxonomies`, one `{level, predicate, value}` entry per
check, which Cortex shows as the job summary.

## Wiring in Suspicious

- Enable it by naming it in `integrations.cortex.analyzers.header` in
  `settings.json`. The value is the Cortex analyzer name with the version suffix:
  **`Mail_Header_Analyzer_1_0`**. A wrong name (an older docs example used
  `MailHeader_4_0`) logs "Header analyzer '...' not found", no header job is
  launched and the verdict goes without it.
- `cortex_job` launches the analyzer named there for `mail_header` observables of a
  mail case; its report is an input to scoring like the other analyzers. For a
  `.eml` file the configured `header` analyzer is left out of the generic file
  analyzers.
- The analyzer image is built from `Analyzers/MailHeaderAnalyzer/Dockerfile`
  (Python 3.14 slim, runs as the unprivileged uid 1001).

## Tests

The logic in `mail_header_analysis.py` uses only the standard library, so its tests
run without the image:

```bash
cd Analyzers/MailHeaderAnalyzer && python -m pytest tests
```
