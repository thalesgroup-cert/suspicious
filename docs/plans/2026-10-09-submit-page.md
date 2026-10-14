# Submit Page Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Submit page's mode choice unambiguous, tell users the real upload limit before they upload, make pasted-indicator parsing legible, and clean up the page's repeated and misplaced guidance.

**Architecture:** One backend field set on the existing `GET /api/submit/config/`; frontend changes in `features/submit/*` and `pages/SubmitPage.tsx`. Visual verification uses the rebuilt `suspicious_ui` image and Playwright.

**Tech Stack:** Django REST, React 19, MUI 9.4, react-dropzone 20, react-hook-form + zod, Vitest 4 browser mode, Playwright.

**Spec:** the approved chat design of 2026-10-09 (audit S1 to S8; decisions: "Indicators default, config endpoint for the limit"). No separate spec file: bounded change to an existing page.

## Global Constraints

- No route change; no change to any page other than Submit; no new dependency; theme tokens only (no hardcoded colours); every theme keeps its contrast floor.
- Every design decision has a one-line reason (anti-slop C-1); UI strings plain, no filler, no fabricated claims. The only numbers shown to users come from the backend config or from counting the user's own input.
- Remove inline `sx` `letterSpacing` and `fontWeight` above 800 from every heading, title and label in the Submit page and `features/submit/components/cards.tsx` (they caused "Fileupload", the same bug class as Home). Use theme typography variants instead.
- Backend tests run against the working tree: `cd deployment && docker compose --env-file .env run --rm --no-deps -v /home/forensics/suspicious/suspicious/Suspicious/Suspicious:/app/Suspicious suspicious python manage.py test <labels>`; rebuild the backend image to serve changes on :9020: `docker compose --env-file .env build suspicious && docker compose --env-file .env up -d suspicious suspicious_celery suspicious_celery_beat`.
- Frontend toolchain: Node 22 (`export PATH=$CLAUDE_JOB_DIR/tmp/node-v22.13.1-linux-x64/bin:$PATH`), `npx pnpm@11.1.3`, `npx vitest run`, `npx tsc -b`, `npx eslint .` (0 errors; 4 existing warnings are fine).
- Visual check: `docker compose --env-file .env build suspicious_ui && up -d suspicious_ui`, then a Playwright script under `$CLAUDE_JOB_DIR/tmp` (login as `scripts/theme-sheets.mjs` does; `UI_USER=elena.voss@meridian.example UI_PASS='MeridianDev!2026'`; `CHROMIUM_PATH=$(ls ~/.cache/ms-playwright/chromium_headless_shell-1234/*/chrome-headless-shell)`; theme switch via the `suspicious:theme-hydrate` window event). Baselines of the page before any change: `$CLAUDE_JOB_DIR/tmp/audit-submit` (light/midnight desk+phone, file state, indicators empty and filled).
- The Playwright e2e specs under `suspicious-ui/e2e/` (`submit.spec.ts`, `ioc-road.spec.ts`) may assert the old default mode or copy; update them to match (they are not part of the unit gate and need not be run, but must not be left asserting removed behaviour).
- Never stage anything under `deployment/` (an unrelated uncommitted `compose_apps.yaml` edit lives there).

## Review Focus

- A file of exactly the limit, one byte over, and zero bytes: boundary behaviour. Pinned in Task 2.
- A dropped file of a rejected type or too many files: user sees a plain message, nothing is selected. Pinned in Task 2.
- Config request fails or is still loading: the dropzone still works (no `maxSize` applied, server still enforces), and no "undefined MB" text. Pinned in Task 2.
- Pasted text with prose, a defanged URL, duplicates, and 101 indicators (backend cap `IOC_GROUP_MAX = 100`): counts and "skipped" rows are right and Submit is disabled with a clear reason above the cap. Pinned in Task 3.
- Keyboard-only: mode switch with arrow keys, dropzone opens with Enter/Space, focus visible. Pinned in Task 4.

---

## File Structure

- Modify `Suspicious/Suspicious/api/serializers/submit.py`, `api/views/submit.py`; create `api/tests/test_submit_config.py`.
- Modify `suspicious-ui/src/features/submit/api.ts`, `types.ts`; create `features/submit/formatBytes.ts` (+ test).
- Modify `suspicious-ui/src/features/submit/parseIndicators.ts` (+ its test), and the indicator preview in `pages/SubmitPage.tsx`.
- Modify `suspicious-ui/src/features/submit/components/cards.tsx` (mode selector), `pages/SubmitPage.tsx`, `pages/__tests__/SubmitPage.test.tsx`, `e2e/submit.spec.ts`, `e2e/ioc-road.spec.ts` if affected.

---

### Task 1: Backend, expose the limits on the submit config

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/submit.py:250-251`, `api/views/submit.py:145-157`
- Create: `Suspicious/Suspicious/api/tests/test_submit_config.py`

**Interfaces:**
- Produces: `GET /api/submit/config/` returns `{"status": "success", "data": {"suspicious_email": str, "max_file_bytes": int, "max_indicators": int}}` where `max_file_bytes` is `settings.SUBMIT_FILE_MAX_BYTES` (fallback `DEFAULT_UPLOAD_MAX_BYTES`, the same fallback the file serializer uses) and `max_indicators` is `IOC_GROUP_MAX` from `api/views/submit.py`.

- [ ] **Step 1: Write the failing tests** (`APITestCase`, `force_authenticate`): (a) response contains `max_file_bytes == settings.SUBMIT_FILE_MAX_BYTES` and `max_indicators == 100`; (b) with `@override_settings(SUBMIT_FILE_MAX_BYTES=1234)` the value is 1234; (c) unauthenticated request is rejected (401/403 as the view's `IsAuthenticated` gives). Read `api/views/submit.py` and `api/serializers/submit.py` first for the exact import of `IOC_GROUP_MAX` and `DEFAULT_UPLOAD_MAX_BYTES`.
- [ ] **Step 2: Run to see them fail:** `python manage.py test api.tests.test_submit_config` (via the mount command above). Expected: KeyError `max_file_bytes`.
- [ ] **Step 3: Implement.** Add `max_file_bytes = IntegerField()` and `max_indicators = IntegerField()` to `SubmitConfigSerializer`; build the dict in the view from settings and the constant (do not duplicate the number 100; import `IOC_GROUP_MAX`).
- [ ] **Step 4: Run** `api.tests.test_submit_config api.tests.test_submit_indicators api.tests.test_api_endpoints`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(api): expose upload and indicator limits on submit config`.

---

### Task 2: Show and enforce the file limit in the dropzone

**Files:**
- Create: `suspicious-ui/src/features/submit/formatBytes.ts`, `suspicious-ui/src/features/submit/__tests__/formatBytes.test.ts`
- Modify: `suspicious-ui/src/features/submit/api.ts:58-61`, `types.ts:1-6`, `pages/SubmitPage.tsx` (config query ~lines 83-96, dropzone ~lines 110-117 and its UI text), `pages/__tests__/SubmitPage.test.tsx`

**Interfaces:**
- Produces: `export function formatBytes(n: number): string` (binary units, one decimal at most: 5242880 -> "5 MB", 1536 -> "1.5 KB", 0 -> "0 B"; label "MB" for MiB as the product already says MB elsewhere, say so in one comment).
- Produces: `getSubmitConfig(): Promise<{ suspiciousEmail: string; maxFileBytes: number; maxIndicators: number }>`.

Changes (each with its reason):
1. The config query ALWAYS runs when `me` is loaded (the old code skipped it when `VITE_SUSPICIOUS_EMAIL` was set, which would also skip the limit). The email still prefers the env value when set. Reason: the limit must come from the server, not the build.
2. Dropzone: `maxSize: config?.maxFileBytes` only when the config has loaded (undefined otherwise: server still enforces); `onDropRejected` sets a plain error from the first rejection: `file-too-large` -> "<name> is <size>; the limit is <limit>."; `file-invalid-type` -> "<name> is not an accepted file type."; `too-many-files` -> "Upload one file at a time."; anything else -> the library message. Show the error under the dropzone (role="alert"), clear it on the next successful drop or on Remove. Reason: reject in the browser, with the real limit, instead of after the upload.
3. Dropzone helper text: replace "Limits and acceptance rules are enforced server-side." with "One file per submission, up to <limit>." when the limit is known, and "One file per submission." when not.
4. `isDragReject` styles the dropzone with the theme's `error` colour; `isDragAccept` with `primary`.

- [ ] **Step 1: Failing tests.** `formatBytes` table (0, 1, 1023, 1024, 1536, 5242880, 1073741824). SubmitPage tests following the file's existing mocking style (read it first): (a) with config `max_file_bytes: 1024`, dropping a 2048-byte file shows "is 2 KB; the limit is 1 KB" and no file chip; (b) a file of exactly 1024 bytes is accepted; (c) a 0-byte file is accepted by the dropzone (the server rejects it: do not invent a client rule unless the serializer says so; the server message "Uploaded file is empty." must surface through the existing error path, assert nothing new here); (d) config request pending or failing: dropzone helper text has no "undefined", a 10 MB file is still selectable; (e) helper text shows "up to 5 MB" for `max_file_bytes: 5242880`.
- [ ] **Step 2: Run to fail; implement; run to pass:** `npx vitest run src/features/submit src/pages/__tests__/SubmitPage.test.tsx`.
- [ ] **Step 3: Visual check at 1440 and 390** (light, midnight): helper text; then in Playwright drop a generated 6 MB file (rebuild the backend image first so :9020 serves `max_file_bytes`) and view the rejection message.
- [ ] **Step 4:** `npx vitest run`, `npx tsc -b`, `npx eslint .`.
- [ ] **Step 5: Commit** `feat(ui): show the real upload limit and reject oversized files before upload`.

---

### Task 3: Legible indicator parsing

**Files:**
- Modify: `suspicious-ui/src/features/submit/parseIndicators.ts`, `__tests__/parseIndicators.test.ts`, the preview block in `pages/SubmitPage.tsx` (the list of detected rows, the summary line and the Submit button disabled logic), `pages/__tests__/SubmitPage.test.tsx`

**Interfaces:**
- Produces: `parseIndicators(text): ParsedIndicator[]` unchanged signature. New behaviour: consecutive tokens that do not classify as an indicator are collapsed into ONE row (`type: null`, `value`/`raw` the words joined with a single space), so "not a thing" is one skipped row instead of three. Classified tokens keep their own rows, order is preserved, duplicates (case-insensitive) are dropped as before.
- Produces: the summary line reads "<n> will be submitted" and, when there are skipped rows, " · <m> skipped" (counts of valid rows and of unrecognised rows). When `n > maxIndicators` (from the config, default 100 when unknown) the line becomes "<n> indicators; the limit is <max>." in the `error` colour and Submit is disabled. When `n === 0` and text is non-empty: "Nothing recognisable yet. Add a URL, domain, IP or hash." Skipped rows render muted (`text.secondary`) with the label "skipped" instead of "unrecognised" (reason: the label says what happens to them).

- [ ] **Step 1: Failing tests** in `parseIndicators.test.ts` (read the existing ones first and keep them green unless they pin the old per-word behaviour, in which case update them and say so): (a) "not a thing mail.example.org 999.1.1.1" gives rows `not a thing` (null), `mail.example.org` (domain), `999.1.1.1` (null); (b) "hxxp://evil[.]example/login?x=1, 198.51.100.7" gives url + ip, refanged; (c) duplicates differing in case collapse; (d) two unrecognised runs separated by a valid token stay two rows; (e) empty and whitespace-only input give `[]`. SubmitPage tests: summary text for a mixed paste; 101 valid indicators disable Submit and show the limit message; the old text "indicator(s)" no longer appears.
- [ ] **Step 2: Run to fail; implement; run to pass.**
- [ ] **Step 3: Visual check:** Indicators panel with the audit paste in light and midnight at 1440 and 390; view them.
- [ ] **Step 4:** `npx vitest run`, `npx tsc -b`, `npx eslint .`.
- [ ] **Step 5: Commit** `feat(ui): collapse prose into one skipped row and state what will be submitted`.

---

### Task 4: Mode selector with real semantics, Indicators first and default

**Files:**
- Modify: `suspicious-ui/src/features/submit/components/cards.tsx` (`ModeSelectorCard`), `pages/SubmitPage.tsx` (mode state default, selector markup), `pages/__tests__/SubmitPage.test.tsx`, `e2e/submit.spec.ts` and `e2e/ioc-road.spec.ts` if they assume File first

**Interfaces:**
- Produces: the mode selector is a MUI `ToggleButtonGroup` (`exclusive`, `aria-label="Submission type"`), two `ToggleButton`s, "Indicators" FIRST and default, "File" second; each shows icon, title and one short line (subtitle shortened to what differs: Indicators "URLs, domains, IPs, hashes, or an IOC-list file"; File "An email (.eml, .msg) or any attachment"). The "Recommended" and "Selected" chips are removed. Selected state uses the theme's primary tint and a visible check icon; unselected uses the theme card border (no heavy black border). On phones the two buttons stack. Reason: `ToggleButtonGroup` gives radio-like keyboard behaviour and `aria-pressed` for free; two visual signals (Recommended and Selected) conflicted.

- [ ] **Step 1: Failing tests:** default view is Indicators (its panel visible, file dropzone absent); `getByRole("group", { name: "Submission type" })` contains two buttons, Indicators first, `aria-pressed` true on Indicators; clicking File switches panel and `aria-pressed`; keyboard: focus the group and press Tab then Space/Enter on File switches (userEvent); "Recommended" and "Selected" text are gone.
- [ ] **Step 2: Run to fail; implement; run to pass.** Update e2e specs that assume File first (read them; change selectors/steps, keep their intent).
- [ ] **Step 3: Visual check:** light, midnight, paper, high_contrast, cyber at 1440 and 390; view them; selected and unselected must be distinguishable in every theme (high_contrast without relying on tint alone).
- [ ] **Step 4:** `npx vitest run`, `npx tsc -b`, `npx eslint .`.
- [ ] **Step 5: Commit** `feat(ui): mode selector as a toggle group; Indicators first and default`.

---

### Task 5: One guidance card, notes where they apply, disabled state, headings

**Files:**
- Modify: `suspicious-ui/src/pages/SubmitPage.tsx`, `features/submit/components/cards.tsx` if the guidance helpers live there, `pages/__tests__/SubmitPage.test.tsx`

Changes (each with its reason):
1. Merge "Guidance" and "Accepted inputs" into one card titled "What to submit": the three guidance lines as plain text (no chip styling: they are not controls) plus the accepted-inputs list. Keep "Forward suspicious email" as its own card. Reason: the same facts appeared three times and the chips looked clickable.
2. Move "Related indicators submitted together are correlated as one case. Keep unrelated artifacts in separate submissions." into the Indicators panel (under the textarea), and remove the page-bottom alert. File mode does not show it. Reason: it explains indicator batching and belonged beside the input.
3. Disabled primary button ("Upload file", "Submit"): use MUI's disabled palette (`action.disabledBackground`/`action.disabled`) so it reads as disabled in every theme; check contrast of the label against the disabled background is not required (disabled controls are exempt) but it must not look enabled.
4. Page title: `variant="h4"` with theme sizing and the description in `body2`/`text.secondary`; panel titles ("Indicators", "File upload") use `variant="h5"`; remove every inline `fontWeight` above 800 and every inline `letterSpacing` on headings/labels on this page.
5. On phones the "What to submit" and "Forward suspicious email" cards come after the form (already the case); verify no horizontal scroll.

- [ ] **Step 1: Failing tests:** the page has exactly one element with text "What to submit" and none with "Accepted inputs"; the correlation sentence appears once and only in Indicators mode (switch modes and assert); a disabled submit button has `disabled` and computed `opacity`/background not equal to the enabled one (assert `getByRole("button", { name: "Submit" })` is disabled with an empty textarea); heading text "File upload" has computed `letter-spacing` of `normal` or >= -0.01em of the font size.
- [ ] **Step 2: Run to fail; implement; run to pass.**
- [ ] **Step 3: Visual check** at 1440 and 390 in light, midnight, paper, high_contrast, cyber (empty Indicators, filled Indicators, File with a file); view them; check `scrollWidth <= innerWidth` at 390.
- [ ] **Step 4:** `npx vitest run`, `npx tsc -b`, `npx eslint .`.
- [ ] **Step 5: Commit** `feat(ui): single guidance card, correlation note beside the input, honest disabled state`.

---

### Task 6: Final verification and delivery report

- [ ] **Step 1:** Backend `api.tests.test_submit_config api.tests.test_submit_indicators api.tests.test_api_endpoints dashboard`; full frontend suite, `tsc -b`, `eslint .`.
- [ ] **Step 2:** Final captures of Submit at 1440 in all 17 themes (`scripts/theme-sheets.mjs` does not cover `/submit`; write a small variant under `$CLAUDE_JOB_DIR/tmp`) and at 390 for four themes, in File and Indicators states; compare with `audit-submit`.
- [ ] **Step 3:** Anti-slop delivery report: PASS or FAIL with evidence for claims without a source, fabricated content, decisions without a reason, anything delivered without being run, UI strings and comments.
- [ ] **Step 4:** Append deferred items to `docs/plans/ui-redesign-backlog.md`; `mem_save` a short note.
- [ ] **Step 5: Commit** any doc change.

---

## Self-review

- **Spec coverage:** S1 Task 4; S2 Task 3; S3 Tasks 1 and 2; S4 and S5 and S6 and S7 Task 5. S8 (page title too small) is NOT resolved by this plan: every page title uses the base h4 (16px) and needs a global page-title scale decision.
- **Placeholders:** none; test fixtures that depend on existing mocking style say to read the file first.
- **Type consistency:** `getSubmitConfig` returns the same camelCase shape in Tasks 2 and 3; `maxIndicators` default 100 is used only when the config is unknown; `max_file_bytes` and `max_indicators` are named identically in the backend, the types and the tests.
