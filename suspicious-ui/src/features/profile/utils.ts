import type { UserProfile } from "@/features/profile/api";

export const LOCAL_PROFILE_KEY = "suspicious.profile.local";

export function readLocalProfile(): Partial<UserProfile> | null {
  try {
    const raw = localStorage.getItem(LOCAL_PROFILE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function writeLocalProfile(patch: Partial<UserProfile>) {
  try {
    const next = { ...(readLocalProfile() ?? {}), ...patch };
    localStorage.setItem(LOCAL_PROFILE_KEY, JSON.stringify(next));
  } catch { /* ignore */ }
}

export function initials(first?: string, last?: string) {
  const f = (first ?? "").trim()[0] ?? "";
  const l = (last ?? "").trim()[0] ?? "";
  return (f + l).toUpperCase() || "U";
}

export function apiErrorText(err: unknown) {
  const e = err as any;
  const data = e?.response?.data;
  const msg =
    e?.message || data?.detail || data?.error ||
    (typeof data === "string" ? data : null) || "Request failed";
  const status = e?.response?.status;
  return status ? `${status}: ${msg}` : String(msg);
}
