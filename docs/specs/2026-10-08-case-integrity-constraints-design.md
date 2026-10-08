# Case integrity: database constraints and a tighter `CaseCreator`

## Problem
Several models express "exactly one of these targets" or "this road excludes
that road" only in code. Nothing in the database stops a row that breaks the
rule, and the 2026-10-07 prod check found two surprises:

| Check on prod | Result |
|---|---|
| `AnalyzerReport`, targets set | 235,985 of 235,985 rows have exactly 1 |
| `CaseArtifact`, `ObservableGroupArtifact` | 46,133 and 129 rows, all exactly 1 |
| allow/deny lists, duplicates | 0 in every table |
| `Case` roads set | 45,918 have 1, **97 have 2**, 46 have none |

The 97 two-road cases are all `fileOrMail` + `nonFileIocs`, the last created
2026-10-07, so something creates them today. The 46 no-road cases are old
(last 2026-09-07).

## Finding: most of the 97 are probably by design
A non-mail file upload returns `(file_instance, hash_instance)` from
`CaseHandler._handle_file_form`; `validate_forms` puts both in the result, and
`CaseCreator.create_case` loops over every artifact and attaches each to its
own link (`fileOrMail` for the file, `nonFileIocs` for its hash). On dev, the
only two-road case is exactly that: a file plus its own hash. The hash link is
also what makes the file's hash analyzer reports show up on the case
(`collect_case_targets` reads hashes only through `nonFileIocs`).

So "a file case also has a hash IOC" is a deliberate shape. The prod query Q1
below must confirm that all 97 prod cases are file + hash; any mail + IOC
case would be a genuine bug to fix separately.

## Goals
- Enforce, in the database, the rules that already hold for every prod row.
- Document and test the allowed `Case` shapes in code, without a constraint
  that would reject the file + hash pair.
- Change no existing row.

## Non-goals
- An "exactly one road" constraint on `Case` (it would reject the 97 file +
  hash cases and the 46 empty ones).
- Reworking `Case.fileOrMail` / `nonFileIocs` into the multi-row relations
  (phase 3, conditional).
- Merging `CaseArtifact` with the `CaseHas*` pair (separate spec).

## Design

### 1. Constraints (one migration per app, `AddConstraint`)
| Model | Constraint | Prod evidence |
|---|---|---|
| `AnalyzerReport` | exactly one of the 8 target FKs is set | verified |
| `CaseArtifact` | exactly one of file, hash, url, ip, mail is set | verified |
| `ObservableGroupArtifact` | exactly one of url, ip, hash, domain is set | verified |
| `Case` | `observable_group` set implies `fileOrMail` and `nonFileIocs` are null | verified (all 75 group cases are group-only) |
| `CaseHasFileOrMail` | exactly one of file, mail is set | Q3 |
| `CaseHasNonFileIocs` | exactly one of url, ip, hash is set | Q3 |
| allow/deny lists | one row per domain, IP or hash (`UniqueConstraint`) | verified for duplicates; Q4 for NULL targets |

Written as `CheckConstraint(condition=...)` with the project's naming
(`<model>_<rule>_chk`). The sum-of-booleans form, for example
`Q(a__isnull=False) + ...`, is not expressible in `Q`, so each rule is an
`OR` of the valid shapes. MariaDB enforces check constraints and Django
validates them in `full_clean`, so the admin shows a form error instead of a
database error.

### 2. `CaseCreator` guard (code, no schema)
In `create_case`, after the artifact loop, compute the shape from the links
that were set and assert it is one of:

- mail only;
- file, optionally with that file's own hash (`file.linked_hash`);
- one or more URL, IP or hash IOCs;
- an observable group alone.

Any other combination logs a warning with the case id and the keys, and
still creates the case (no behaviour change for users). A test per allowed
shape and one for the warning. The same helper is the single place the rule
is written down, and the models guide links to it.

### 3. Conditional: several IOC bundles per case
`_create_case_has_iocs` creates one `CaseHasNonFileIocs` row per artifact,
and `case.nonFileIocs` keeps only the last one assigned. A submission with
both an IP and a hash would leave the first bundle unreachable from
`collect_case_targets`, so that IOC's analyzer reports would not appear on the
case. Prod query Q2 counts cases with more than one bundle row.

- If Q2 is 0: nothing to do; the guard in section 2 keeps it that way.
- If Q2 is above 0: a follow-up spec changes the read path (`collect_case_targets`,
  `score_process/scoring/collect.py`, the MISP and TheHive connectors) to read
  the reverse relation (all bundle rows). The constraint on
  `CaseHasNonFileIocs` stays valid because every row still has exactly one IOC.

## Rollout
1. Run Q1 to Q4 on prod (below) and paste the results.
2. Deploy section 2 first (code only, a warning at worst).
3. Apply the constraint migrations off-peak. `ADD CONSTRAINT CHECK` validates
   every row and may rebuild the table in MariaDB. For the small tables
   (`Case` 46k rows, `CaseArtifact` 46k, the `CaseHas*` pair) that is
   seconds. `AnalyzerReport` is 2.6 GB: test the `ALTER` with
   `ALGORITHM=NOCOPY` on a restored copy first (it errors instead of
   rebuilding if it would copy), and skip the `AnalyzerReport` constraint if
   it would lock writes for minutes.
4. Back out by dropping the constraint (`RemoveConstraint`); no data is touched.

## Prod queries (read-only)
```sql
-- Q1: what are the two-road cases?
SELECT (f.file_id IS NOT NULL) has_file, (f.mail_id IS NOT NULL) has_mail,
       (n.url_id IS NOT NULL) has_url, (n.ip_id IS NOT NULL) has_ip,
       (n.hash_id IS NOT NULL) has_hash, COUNT(*) cases
FROM case_handler_case c
JOIN case_handler_casehasfileormail f ON f.id = c.fileOrMail_id
JOIN case_handler_casehasnonfileiocs n ON n.id = c.nonFileIocs_id
GROUP BY 1,2,3,4,5;

-- Q2: more than one bundle row per case (an unreachable bundle)
SELECT 'file_or_mail rows per case > 1' t, COUNT(*) n FROM (SELECT case_id FROM case_handler_casehasfileormail GROUP BY case_id HAVING COUNT(*)>1) x
UNION ALL SELECT 'nonfile rows per case > 1', COUNT(*) FROM (SELECT case_id FROM case_handler_casehasnonfileiocs GROUP BY case_id HAVING COUNT(*)>1) x;

-- Q3: bundle shape violations (expect 0)
SELECT 'file_or_mail: both or neither' t, COUNT(*) n FROM case_handler_casehasfileormail WHERE (file_id IS NULL) = (mail_id IS NULL)
UNION ALL SELECT 'nonfile: not exactly one of url/ip/hash', COUNT(*) FROM case_handler_casehasnonfileiocs
 WHERE (url_id IS NOT NULL)+(ip_id IS NOT NULL)+(hash_id IS NOT NULL) <> 1;

-- Q4: allow/deny rows with no target (expect 0)
SELECT 'allow_domain' t, COUNT(*) n FROM settings_allowlistdomain WHERE domain_id IS NULL
UNION ALL SELECT 'deny_domain', COUNT(*) FROM settings_denylistdomain WHERE domain_id IS NULL
UNION ALL SELECT 'allow_ip', COUNT(*) FROM settings_allowlistip WHERE ip_id IS NULL
UNION ALL SELECT 'allow_file', COUNT(*) FROM settings_allowlistfile WHERE linked_file_hash_id IS NULL
UNION ALL SELECT 'campaign_allow', COUNT(*) FROM settings_campaigndomainallowlist WHERE domain_id IS NULL;
```
Dev results for reference: Q1 one case, file + hash; Q2 to Q4 all 0.

## Testing
- Each constraint: a test that creates a valid row, then a row that breaks
  the rule and expects `IntegrityError` (the test DB is SQLite, which
  enforces `CHECK`).
- `CaseCreator`: one test per allowed shape (mail; file with its hash; URL, IP
  and hash IOCs; group) asserting no warning, and one for a mail plus a URL
  asserting the warning and that the case is still created.
- The existing `case_handler`, `api` and `connectors` suites pass unchanged.
- Writers: `grep` every creator of the constrained models (the Cortex
  report writer, `CaseCreator`, the allow/deny admin imports) and cover each
  with a test, because an existing code path that writes two targets starts
  raising `IntegrityError` the day the constraint lands.

## Risks
- **A writer I did not find** produces a violating row and now fails. Mitigated
  by the grep, the test suite, and applying the migrations after the guard has
  logged for a few days.
- **Lock time on large tables** during `ADD CONSTRAINT`. Mitigated by the
  `NOCOPY` test and off-peak timing; `AnalyzerReport` may be skipped.
- **Q1 shows mail + IOC cases.** Then the guard's warning is the right alert
  and a separate fix to the submit flow is needed; the constraints in
  section 1 are unaffected.
