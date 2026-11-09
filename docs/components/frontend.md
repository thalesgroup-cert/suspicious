# Frontend (React UI)

The web UI is a single-page app in `suspicious-ui/`, served by Nginx
(port 9021) in production and proxied to the Django backend in development.

## Stack

- React 19 + TypeScript, built with Vite.
- Material-UI (MUI v9) for components.
- React Router v8 for routing.
- TanStack Query v5 for server state; Zustand for client state.
- React Hook Form + Zod for forms and validation.

## Pages

Submit, Submissions/Investigations, Campaigns, Dashboard, Settings, Profile,
and About. These map to the flows in the
[User Guide](../user-guide/submitting.md).

Settings is a console of sections, shown by group (Detection lists, Access,
Ingestion, Scoring, Integrations). Two are conditional: the **AI model** card
(`/settings/ai_model`, `features/aiModel/`) is listed only for users in the
`Admin` group and only while the `ai_model` connector is enabled
(`requiresGroup` / `requiresConnector` in `features/settings/components/sections.tsx`).
Its five tabs are Overview, Candidate, Shadow, Versions and Ledger. In the case
drawer and the investigation overview, `AiAssessmentSection` renders the
case's AI model assessment when the API returns an `ai_assessment`. See
[Profile & Settings](../user-guide/profile.md#ai-model-card).

## Testing

- Unit/component tests: Vitest + jsdom + `@testing-library`.
- End-to-end: Playwright.

## Local development

```bash
cd suspicious-ui
pnpm install
pnpm dev        # Vite dev server on port 5173
pnpm test       # Vitest
pnpm test:e2e   # Playwright
```
