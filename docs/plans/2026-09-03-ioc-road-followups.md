# IOC-analysis-road — post-merge follow-ups

Surfaced by the whole-branch review of `impl/ioc-analysis-road` (merged into
`design/ioc-road-and-verdict-model`, 2026-09-03). None of these blocked the
merge; they are tracked here so they are not lost with the SDD scratch workspace.

## 1. `api/__init__.py` CI test-discovery gap — ✅ DONE 2026-09-03

`Suspicious/Suspicious/api/` was the only Django app with no `__init__.py`, so
Django's no-label test discovery (CI `backend-test`) never recursed into it —
the entire `api/tests/` tree (198 tests) was silently skipped.

Fixed in one commit: added the empty `api/__init__.py`; replaced the historical
`suspicious/test_urls.py` stub (a host-without-Docker workaround, obsolete since
CI runs in the image) with `from suspicious.urls import urlpatterns`; fixed one
rotted mock in `test_profile_avatar.py` (`get_s3_presign_client` wasn't patched).
Suite went 658 → 856, all green. The `@override_settings(ROOT_URLCONF=
"suspicious.urls")` decorators on the IOC-road test modules are now redundant but
left in place (harmless).

## 2. Backend / frontend indicator classifier disagree — ✅ DONE 2026-09-03

`_classify` now uses `_DOMAIN = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.I)`,
the same pattern as `parseIndicators.ts`. `user@host`, `host:port`, all-numeric
strings now classify as `None` on both sides.

## 3. `ioc_level` vocabulary widening on shared rows — ✅ DONE 2026-09-03

`finalise_ioc_group` now maps the categorical band onto the legacy vocabulary
(`_BAND_TO_IOC_LEVEL`: Safe→safe, Inconclusive→info, Suspicious→suspicious,
Dangerous→malicious) before writing `ioc_level`, and skips the write entirely
when the row already carries a stronger sticky marker (`critical`,
`SAFE-ALLOW_LISTED`). The Case verdict itself stays categorical
(`case.results = Result.DANGEROUS` etc.).

## 4. URL-planner `analyzed_url` blind spot — ✅ DONE 2026-09-03

`observable_reports` now `select_related("url__analyzed_url")` and, for a URL
observable whose `analyzed_url` is set (collapsed/reused by the planner), folds
the representative's `AnalyzerReport` rows into that observable's bucket. Covered
by `test_collapsed_url_observable_shows_representative_reports`.

## 5. `parseObservableGroup` silent fallback (frontend) — ✅ DONE 2026-09-03

Now `console.warn`s with `parsed.error.issues` when a *present* payload fails
validation (still returns `undefined` for the absent/null case without noise).

## 6. `case.analysis_done` semantics differ by road — ✅ DONE 2026-09-03

`finalise_ioc_group` now writes `sum(len(sources))` across observables
(analyzer-report count, matching the mail road's `verdict.n_scored`) instead of
the observable count.

## 7. TheHive alert severity hardcoded — ✅ DONE 2026-09-03

`on_case_finalised` now derives TheHive severity from `case.results`
(Safe→1 / Inconclusive→2 / Suspicious→3 / Dangerous→4); tlp/pap stay 2.

## 8. Scoring-plan Task 14 — `mail_band_escalation` wiring — BLOCKED, needs a design decision

Attempted 2026-09-03, reverted. The plan's self-review assumed the mail signal
path was already isolated from embedded IOCs (Option B: "mail score = AI + YARA +
sandbox only"). It is **not**: `collect_signals` → `process_mail` →
`process_mail_artifact` → `process_ioc` still scores every embedded
URL/IP/hash/domain mail artifact into `score_case`'s signal aggregate. So layering
`mail_band_escalation` on top double-counts embedded IOCs.

Doing this properly requires first stopping `process_mail` from feeding
`mail_artifacts` into the aggregate signal list — a real behavior change to the
mail verdict path with mail-backtest drift, which needs the user's sign-off (it's
the Option-B split the original design called for but the scoring plan never
actually implemented). Not a mechanical follow-up.

`mail_band_escalation` itself stays defined + unit-tested (`test_mail_escalation.py`),
ready for that work.

## 9. VT report enrichment — PRE-MERGE backtest checklist (from the 2026-09-04 whole-branch review)

Before FF-merging `impl/ioc-analysis-road` into `design/`, on a real instance with
this branch's migrations applied, run `python manage.py backtest_scoring --road all`
and `score_accuracy`, and classify every `X -> Y` band transition into one of
these four — none is a regression, but they are distinct and must be named
in the merge notes:

- **(a) `malicious_count == 1`, no `popular_threat_classification` → malicious→suspicious.**
  Intended — the SOC's `8.8.8.8` lone-FP class.
- **(b) `malicious_count == 0`, `suspicious_count == 1` → (was) suspicious→safe.**
  ELIMINATED by the `s >= 1` fix (final-fix commit) — should not appear.
- **(c) `malicious_count == 0`, `reputation <= -25` → safe→suspicious.**
  A deliberate escalation (VT community reputation is a real signal). Spec §5.2.
- **(d) Malicious-verdict confidence rescale** `max(55, min(95, round(50 + 45*m/total)))`.
  Old value was a flat `100`. This only crosses `observable_engine.HIGH_CONFIDENCE = 70`
  at ratio ≥ 44%, so below that VT stops satisfying `decisive_t1` and no longer
  drives Dangerous *on its own* via Rule 1. Mitigating: the branch's own
  `score_process/scoring/fixtures/labelled_cases/*.json` already hand-encode VT
  confidences of 40/45/55 for 3/89, 2/72, 4/64 — this change aligns the parser
  with the categorical engine's reference dataset. Also: safe-verdict confidence
  100→90 has zero IOC-road effect and a tiny mail-road effect (lowers `base_conf`,
  lets the AI signal win marginally more often — escalation direction).

Also spot-check that `AnalyzerReport.enrichment` is populated on new VT reports
(it is, per `test_enrichment_persist`) and optionally run
`python manage.py backfill_enrichment --dry-run` to see the historical count.
