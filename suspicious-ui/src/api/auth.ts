// src/api/auth.ts

import { api, setAccessToken } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import { useColorStore } from "@/styles/colorStore";

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
};

export type LoginResponse = {
  token: string;
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


let _colorsFetched = false; // session-level guard — one fetch per reload

async function hydrateColorsFromServer(): Promise<void> {
  if (_colorsFetched) return;

  try {
    const res = await api.get<{
      semantic_colors: {
        result: Record<string, { main: string }>;
        status: Record<string, { main: string }>;
      };
    }>("/profile/colors/");

    const colors = res.data?.semantic_colors;
    if (colors?.result && colors?.status) {
      useColorStore.getState().hydrateFromProfile(colors as any);
    }

    _colorsFetched = true;
  } catch {
  }
}

// Exposed so tests or manual flows can reset the session guard.
export function resetColorsFetchedFlag() {
  _colorsFetched = false;
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

  setAccessToken(res.data.token);

  hydrateColorsFromServer();

  return res.data;
}

export async function logout(): Promise<void> {
  try {
    await api.post(endpoints.logout);
  } finally {
    setAccessToken(null);
    // Reset the session guard so the next login fetches fresh colors.
    resetColorsFetchedFlag();
  }
}

export async function getMe(): Promise<Me> {
  const res = await api.get<Me>(endpoints.me);

  hydrateColorsFromServer();

  return res.data;
}