# IOC-analysis-road — post-merge follow-ups

Surfaced by the whole-branch review of `impl/ioc-analysis-road` (merged into
`design/ioc-road-and-verdict-model`, 2026-09-03). None of these blocked the
merge; they are tracked here so they are not lost with the SDD scratch workspace.

## 1. `api/__init__.py` CI test-discovery gap — HIGH (do first)

`Suspicious/Suspicious/api/` is the only Django app with no `__init__.py`.
Django's no-label test discovery (what CI `backend-test` runs:
`manage.py test --settings=suspicious.test_settings`) does **not** recurse into
the namespace-package `api/`, so the entire `api/tests/` tree never runs in CI —
~97 pre-existing tests plus ~20 added by this branch. The IOC-road backend tests
pass only under explicit invocation; new `api/tests/*` modules pin
`@override_settings(ROOT_URLCONF="suspicious.urls")` so they *can* be run, but
they do not gate.

Fix is its own task: add `api/__init__.py`, then either repoint
`suspicious/test_settings.py` `ROOT_URLCONF` to the real `suspicious.urls`
(check first why the stub `suspicious/test_urls.py` exists — the connectors
suite + eager-Celery config), or add the `@override_settings` to the ~20
pre-existing api test classes that 404 without it. Turns CI red until complete.

## 2. Backend / frontend indicator classifier disagree

`api/utils/indicators.py::_classify` uses a loose domain heuristic
(`"." in v and " " not in v and "/" not in v`) that accepts `user@example.com`,
`8.8.8.8:80`, `1.2.3.4.5` as `domain`; the frontend `parseIndicators.ts` regex
(`^[a-z0-9.-]+\.[a-z]{2,}$`) rejects them. Preview count can differ from the
server's `observable_count`. Port the frontend regex to `_classify`.

## 3. `ioc_level` vocabulary widening on shared rows

`finalise_ioc_group` writes `"dangerous"` / `"inconclusive"` into
`IP/URL/Hash/Domain.ioc_level`, whose legacy vocabulary is
`safe / info / suspicious / malicious / critical / SAFE-ALLOW_LISTED`. Those rows
are globally shared, so this can clobber the deny-list `critical` marker and the
allow-list markers. Display-only impact today (admin `list_filter`). Decide:
separate field for the IOC-road band, or map bands to the legacy vocabulary.

## 4. URL-planner `analyzed_url` blind spot

With `url_analysis.enabled` (default off), `plan_url_analysis` marks >5
same-domain URLs `SKIPPED` and collapses same-canonical-key URLs to a
representative. `assemble_observables` / `observable_reports` filter
`AnalyzerReport` on the observable itself and never follow `analyzed_url`, so a
skipped/collapsed URL observable renders "no sources / Inconclusive" forever even
though `collect_case_targets` dispatched its `analyzed_url`. Follow `analyzed_url`
in the assembly.

## 5. `parseObservableGroup` silent fallback (frontend)

`suspicious-ui/src/features/investigation/observableGroup.ts::parseObservableGroup`
returns `undefined` on any backend shape change → the investigation page silently
falls back to the legacy analyzer layout. Add a `console.warn` on
`!parsed.success`.

## 6. `case.analysis_done` semantics differ by road

IOC road writes observable-count; mail road writes analyzer-count
(`verdict.n_scored`). Surfaces as `tests_done` in the UI and feeds `_describe`'s
"reused from a prior identical submission" branch. Low impact; note when touching
either path.

## 7. TheHive alert severity hardcoded

`TheHiveConnector.on_case_finalised` passes `severity/tlp/pap = 2/2/2` for every
IOC-group alert. Derive severity from `case.results` (Dangerous → higher).

## 8. Scoring-plan Task 14 — `mail_band_escalation` wiring (not started)

From the scoring-verdict-model plan's own self-review: `mail_band_escalation` is
defined and unit-tested but never called from `get_report` for mail cases with
embedded IOCs. Wiring it needs the embedded-IOC `ObservableVerdict` list
(`collect_case_targets`-derived) computed in `reports.py::get_report` after
`apply_verdict`, then re-save `case.results`. ~5 steps, same shape as the
IOC-road finalise wiring.
