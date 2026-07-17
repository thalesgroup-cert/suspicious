import { env } from "@/lib/runtimeEnv";

// ─── Branding (configured per deployment via runtime env) ───────────────────

export const COMPANY_NAME        = env("VITE_COMPANY_NAME")        ?? "Company";
export const COMPANY_LINK        = env("VITE_COMPANY_LINK")        ?? "/";
export const COMPANY_LOGO_BASE64 = env("VITE_COMPANY_LOGO_BASE64");
export const COMPANY_LOGO_URL    = env("VITE_COMPANY_LOGO_URL");
export const SUPPORT_EMAIL       = env("VITE_SUPPORT_EMAIL")       ?? "support@company.com";

// ─── SSO error mapping ──────────────────────────────────────────────────────

export const SSO_ERROR_MESSAGES: Record<string, string> = {
  provider_unavailable:    "SSO provider is currently unavailable.",
  state_mismatch:          "SSO session expired or invalid. Please try again.",
  nonce_mismatch:          "SSO response could not be verified. Please try again.",
  token_exchange_failed:   "SSO authentication failed. Please try again.",
  userinfo_failed:         "Could not retrieve your account details from SSO.",
  user_resolution_failed:  "Could not link your SSO account. Contact your administrator.",
  account_disabled:        "Your account is disabled. Contact your administrator.",
};

/** Reads ?sso_error=<code> off the current URL and maps it to a message. */
export function initialSsoError(): string | null {
  const ssoError = new URLSearchParams(window.location.search).get("sso_error");
  if (!ssoError) return null;
  return SSO_ERROR_MESSAGES[ssoError] ?? `SSO error: ${ssoError}`;
}
