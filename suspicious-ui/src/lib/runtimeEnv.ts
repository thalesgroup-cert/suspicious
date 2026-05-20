// Runtime environment access.
//
// The production image is built once (in CI) with no .env, so build-time
// VITE_* values are absent. Instead the container's entrypoint writes
// `window.__ENV__` into /env-config.js at startup from the container's
// environment variables. One image, configured per deployment.
//
// In dev (`vite dev`) window.__ENV__ is the empty placeholder, so we fall
// through to import.meta.env, which the dev server populates from .env.

declare global {
  interface Window {
    __ENV__?: Record<string, string>;
  }
}

export function env(key: string): string | undefined {
  const runtime =
    typeof window !== "undefined" ? window.__ENV__ : undefined;
  const fromRuntime = runtime?.[key];
  if (fromRuntime !== undefined && fromRuntime !== "") {
    return fromRuntime;
  }
  const fromBuild = (import.meta.env as Record<string, string | undefined>)[key];
  return fromBuild !== undefined && fromBuild !== "" ? fromBuild : undefined;
}
