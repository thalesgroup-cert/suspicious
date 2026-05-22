# Frontend (React UI)

The web UI is a single-page app in `suspicious-ui/`, served by Nginx
(port 9021) in production and proxied to the Django backend in development.

## Stack

- React 19 + TypeScript, built with Vite.
- Material-UI (MUI v9) for components.
- React Router v7 for routing.
- TanStack Query v5 for server state; Zustand for client state.
- React Hook Form + Zod for forms and validation.

## Pages

Submit, Investigations, Campaigns, Alerts, Settings, Dashboard, and Profile.
These map to the flows in the [User Guide](../user-guide/submitting.md).

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
