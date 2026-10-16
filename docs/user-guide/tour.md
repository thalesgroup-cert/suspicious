# UI tour

A short animated look at each page of the web UI. The clips are recorded
from the real app with fictional data ("Meridian Group"). For a narrated,
subtitled walkthrough, see the [product demo](../demo.md).

## Sign in

Sign in with SSO, or expand the local-account form.

![Login page: expand the local sign-in form, enter credentials and land on the home page](../assets/gifs/login.gif)

## Home

The month's verdicts across the organisation, your share of reports, and your latest submissions.

![Home page: threat distribution, monthly share and recent submissions](../assets/gifs/home.gif)

## Submit

Paste URLs, domains, IPs and hashes, or upload a file. Types are detected
automatically. See [Submitting](submitting.md).

![Submit page: switch between file and indicators, paste indicators, submit, and the case opens](../assets/gifs/submit.gif)

## My submissions

Search your reports and open any case to see its verdict and analysis.

![My submissions: search, open a case, switch between Overview and Analysis](../assets/gifs/submissions.gif)

## Investigation

The CERT workspace: every case, the explained verdict and the per-source breakdown.
See [Investigations](investigations.md).

![Investigation workspace: open a case, read why it was scored Dangerous, expand the source breakdown](../assets/gifs/investigation.gif)

## Dashboard

Volumes, outcomes and top reporters, month over month. See [Dashboard](dashboard.md).

![Dashboard: KPI cards, outcomes, what was reported and top reporters](../assets/gifs/dashboard.gif)

## Campaigns

Similar messages clustered with ML embeddings, so a coordinated wave stands out.
See [Campaigns](campaigns.md).

![Campaigns: embedding map, mail volume and campaigns in the period](../assets/gifs/campaigns.gif)

## Profile and Settings

Personal preferences and appearance for everyone; allow/deny lists, the email
feeder and analyzer scoring for Admin and CERT. See [Profile & Settings](profile.md).

![Profile: preferences, appearance, colours and avatar](../assets/gifs/profile.gif)

![Settings console: allowlist, denylist and analyzer scoring](../assets/gifs/settings.gif)

## Regenerating these clips

```bash
cd suspicious-ui
pnpm demo:gifs   # record every page (demo/pages.demo.ts), then encode to docs/assets/gifs/
```

Needs `ffmpeg` and Playwright's Chromium (`pnpm exec playwright install chromium`).
