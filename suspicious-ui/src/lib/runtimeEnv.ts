
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
