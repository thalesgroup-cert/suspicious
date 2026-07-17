
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
  semantic_colors?: {
    result: ResultColors;
    status: StatusColors;
  };
  theme?: string;
  auto_seasonal?: boolean;
};

export type LoginResponse = {
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

  hydrateAppearanceFromMe(res.data);

  return res.data;
}