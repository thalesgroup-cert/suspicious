# case_handler

Case CRUD and lifecycle.

## Case shapes and integrity rules

Allowed shapes:

1. A mail alone.
2. A file, optionally with that file's own hash. This pair is deliberate (97 prod cases).
3. ip/url/hash IOCs without a mail or file.
4. An observable group alone.

For anything else `CaseCreator` logs `Case <id> has an unexpected shape: <shape>` (WARNING) but still creates the case.

There is intentionally no "exactly one road per case" constraint, because of the file + hash pair.

Database constraints:

- `case_group_excludes_other_roads_chk`: a group case has no mail/file or IOC-bundle link.
- `caseartifact_one_target_chk`, `observablegroupartifact_one_target_chk`, `casehasfileormail_one_target_chk`, `casehasnonfileiocs_one_target_chk`: exactly one target set.
- `analyzerreport_one_target_chk`: see `cortex_job`.
- Unique allow/deny entries: `uniq_allowlistdomain_domain`, `uniq_denylistdomain_domain`, `uniq_campaigndomainallowlist_domain`, `uniq_allowlistip_ip`, `uniq_allowlistfile_hash`.
