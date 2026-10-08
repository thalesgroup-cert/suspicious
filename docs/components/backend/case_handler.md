# case_handler

Case CRUD and lifecycle.

## Case shapes and integrity rules

Allowed shapes:

1. A mail alone.
2. A file, optionally with that file's own hash. This pair is deliberate (97 prod cases).
3. ip/url/hash IOCs without a mail or file.
4. An observable group alone.

The shape guard only warns: for any unexpected shape `CaseCreator` logs `Case <id> has an unexpected shape: <shape>` (WARNING). The one combination the database refuses is a group case that also has a mail/file or IOC-bundle link (`case_group_excludes_other_roads_chk`); `_attach_observable_group` would raise `IntegrityError` there (no current caller does this).

There is intentionally no "exactly one road per case" constraint, because of the file + hash pair.

Database constraints:

- `case_group_excludes_other_roads_chk`: a group case has no mail/file or IOC-bundle link.
- `caseartifact_one_target_chk`, `observablegroupartifact_one_target_chk`, `casehasfileormail_one_target_chk`, `casehasnonfileiocs_one_target_chk`: exactly one target set.
- `AnalyzerReport` one-target CHECK: deferred (see [models-guide](models-guide.md)).
- Unique allow/deny entries: `uniq_allowlistdomain_domain`, `uniq_denylistdomain_domain`, `uniq_campaigndomainallowlist_domain`, `uniq_allowlistip_ip`, `uniq_allowlistfile_hash`.
