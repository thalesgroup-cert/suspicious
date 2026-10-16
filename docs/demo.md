# Product demo

A guided tour of the web UI, from sign-in to campaign detection. Subtitles are
burned into the video, so it plays silently anywhere.

<!-- Raw HTML is not path-rewritten by MkDocs; this page is served from /demo/, hence "../". -->
<video controls preload="metadata" playsinline
       poster="../assets/demo/suspicious-demo-poster.jpg"
       style="width:100%;border-radius:8px">
  <source src="../assets/demo/suspicious-demo.mp4" type="video/mp4">
  Your browser cannot play this video.
  <a href="../assets/demo/suspicious-demo.mp4">Download the MP4</a>.
</video>

About 100 seconds, 1280×720, no audio. Subtitle files for reuse or translation:
[WebVTT](assets/demo/suspicious-demo.vtt) · [SRT](assets/demo/suspicious-demo.srt).

## What it shows

1. **Sign in** with SSO or a local account.
2. **Home**: the month's verdicts across the organisation, plus your latest submissions.
3. **Submit**: paste URLs, IPs and hashes (defanged forms included) or upload a file.
   Related indicators become one case.
4. **My submissions**: the case opens as soon as it is created, with per-analyzer
   verdicts, confidence and evidence.
5. **Investigation**: the CERT workspace, with an explained verdict and the
   per-source breakdown behind it.
6. **Dashboard**: volumes, outcomes and top reporters, month over month.
7. **Campaigns**: ML-embedding clusters that surface coordinated waves.

All data is fictional ("Meridian Group": `.example` domains and TEST-NET
addresses). Nothing here comes from a real deployment.

## How the video is made

The video is generated, not screen-captured by hand, so it can be refreshed
whenever the UI changes. A [Playwright](https://playwright.dev/) script drives
the real React app with every `/api/**` call mocked, so no backend is needed
and the result is deterministic.

| File | Role |
|------|------|
| `suspicious-ui/demo/suspicious.demo.ts` | The script: scenes and subtitle text |
| `suspicious-ui/demo/fixtures.ts` | Mocked API responses (the fictional data) |
| `suspicious-ui/demo/director.ts` | Burned-in subtitles, visible cursor, `.vtt`/`.srt` export |
| `suspicious-ui/demo/build.sh` | ffmpeg: MP4, poster, README teaser GIF |
| `suspicious-ui/demo/pages.demo.ts` | Caption-free clip per page, used by the [UI tour](user-guide/tour.md) and README |
| `suspicious-ui/demo/build-gifs.sh` | ffmpeg: per-page clips to optimised GIFs in `docs/assets/gifs/` |

To regenerate (needs `ffmpeg` on the `PATH`):

```bash
cd suspicious-ui
pnpm install
pnpm exec playwright install chromium   # first time only
pnpm demo                               # record, then encode into docs/assets/demo/
```

The per-page GIFs have their own pair of commands, `pnpm demo:gifs` (see the [UI tour](user-guide/tour.md#regenerating-these-clips)).

Edit the `say("…")` calls in `suspicious.demo.ts` to change the subtitles, or
add a scene by driving the page the same way the existing ones do. Set
`DEMO_SHOTS=1` to also save a screenshot per scene under `suspicious-ui/demo/out/shots/`.
