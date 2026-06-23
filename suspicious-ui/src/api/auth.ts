//
// Semantic color hydration strategy:
//
//   The backend now embeds semantic_colors directly in GET /auth/me/
//   (via MeResponseSerializer → AuthenticatedUserSerializer).
//
//   This eliminates the previous second roundtrip to /profile/colors/
//   that was fired on every page load. Colors are now available in the
//   very first authenticated response — before any page component mounts.
//
//   Flow:
//     1. login() sets the token, React Query invalidates ["me"]
//     2. ProtectedRoute mounts → useQuery(["me"]) → getMe()
//     3. getMe() receives Me response with semantic_colors embedded
//     4. hydrateColorsFromMe() pushes them into the Zustand colorStore
//     5. Every dashboard panel, chip, and indicator already has the
//        correct user-configured colors by the time they render

import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import { useColorStore } from "@/styles/colorStore";
import { hydrateThemeFromServer } from "@/styles/ThemeStore";
import type { ResultColors, StatusColors } from "@/styles/colorStore";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Me = {
  id: number;
  username: string;
  email: string;
  first_name?: string;
  last_name?: string;
  groups: string[];
  ciso_scope?: string;
  // Embedded by MeResponseSerializer. Optional so the type stays compatible
  // with pre-migration backends that don't yet return these fields.
  semantic_colors?: {
    result: ResultColors;
    status: StatusColors;
  };
  // Theme preference — embedded alongside colors so a single getMe()
  // call gives us everything needed to render the correct appearance.
  theme?: string;
  auto_seasonal?: boolean;
};

export type LoginResponse = {
  // token is still present in the response body for API clients that use the
  // Authorization header — the browser SPA ignores it and relies on the
  // httpOnly cookie set by the server.
  token?: string;
  expiry: string | null;
  user: {
    id: number;
    username: string;
    email: string;
    first_name?: string;
    last_name?: string;
    groups: string[];
  };
};

// ---------------------------------------------------------------------------
// Appearance hydration — called with every successful getMe() response.
// Applies both the color preset and the theme/seasonal preference so the
// correct appearance is active before any page component renders.
// ---------------------------------------------------------------------------

function hydrateAppearanceFromMe(me: Me): void {
  // ── Semantic colors ───────────────────────────────────────────────────────
  try {
    const colors = me.semantic_colors;
    if (colors?.result && colors?.status) {
      useColorStore.getState().hydrateFromProfile(colors);
    }
  } catch {
    // Never surface a color sync error to the auth flow.
  }

  // ── Theme + auto_seasonal ─────────────────────────────────────────────────
  // Only hydrate if the server actually returned these fields.
  // Pre-migration backends that don't include them are silently skipped —
  // the localStorage value (or OS preference) continues to be used.
  try {
    if (me.theme || me.auto_seasonal !== undefined) {
      hydrateThemeFromServer(
        me.theme ?? "light",
        me.auto_seasonal ?? false,
      );
    }
  } catch {
    // Non-fatal.
  }
}

// ---------------------------------------------------------------------------
// Auth API
// ---------------------------------------------------------------------------

export async function login(
  username: string,
  password: string
): Promise<LoginResponse> {
  const res = await api.post<LoginResponse>(endpoints.login, {
    username,
    password,
  });

  // The server sets the httpOnly knox_token cookie in the response — nothing
  // to store here. Colors are hydrated on the subsequent getMe() call which
  // React Query fires automatically via the ["me"] query on mount.

  return res.data;
}

export async function logout(): Promise<void> {
  try {
    await api.post(endpoints.logout);
  } finally {
    // The server deletes the knox_token cookie in the response.
    // Colors stay in localStorage — they won't flash on the login page
    // and will be overwritten by the next user's getMe() on login.
  }
}

// ---------------------------------------------------------------------------
// SSO helper — called by LoginPage on the ?sso=1 redirect. The httpOnly
// knox_token cookie is already set by the OIDC callback, so there is no token
// to read from the URL. Fires getMe() to both verify the cookie and hydrate
// colors in one shot, since the SSO path bypasses the normal
// login() → getMe() sequence.
// ---------------------------------------------------------------------------

export async function hydrateColorsAfterSso(): Promise<void> {
  try {
    await getMe();
  } catch {
    // Non-fatal — the httpOnly cookie is already set by the server;
    // colors fall back to localStorage defaults.
  }
}

export async function getMe(): Promise<Me> {
  const res = await api.get<Me>(endpoints.me);

  // Hydrate both colors and theme from the embedded appearance fields.
  // Runs on: initial page load, hard refresh, SSO callback, tab focus re-auth.
  hydrateAppearanceFromMe(res.data);

  return res.data;
}