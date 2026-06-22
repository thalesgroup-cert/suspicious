//
// All profile-related API calls. The semantic colors endpoints are new;
// everything else matches the existing patterns in the app.

import { api } from "@/api/client";
import type { ResultColors, StatusColors } from "@/styles/colorStore";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type UserProfile = {
  id:                   number;
  function:             string;
  gbu:                  string;
  country:              string;
  region:               string;
  scope?:               string;          // CISOProfile only
  wants_acknowledgement: boolean;
  wants_results:         boolean;
  theme:                 string;
  auto_seasonal:         boolean;
  semantic_colors:       {
    result: ResultColors;
    status: StatusColors;
  };
  creation_date: string;
  last_update:   string;
};

export type AppearancePayload = {
  theme?:           string;
  auto_seasonal?:   boolean;
  semantic_colors?: {
    result?: Partial<ResultColors>;
    status?: Partial<StatusColors>;
  };
};

export type PreferencesPayload = {
  wants_acknowledgement?: boolean;
  wants_results?:         boolean;
};

export type SemanticColorsPayload = {
  semantic_colors: {
    result?: Partial<ResultColors>;
    status?: Partial<StatusColors>;
  };
};

// ---------------------------------------------------------------------------
// GET /api/profile/
// ---------------------------------------------------------------------------

export async function getProfile(): Promise<UserProfile> {
  const { data } = await api.get<UserProfile>("/profile/");
  return data;
}

// ---------------------------------------------------------------------------
// PATCH /api/profile/appearance/
// Updates theme, auto_seasonal, and/or semantic_colors in one request.
// Used by the "Save appearance" button in ProfilePage.
// ---------------------------------------------------------------------------

export async function updateAppearance(
  payload: AppearancePayload
): Promise<UserProfile> {
  const { data } = await api.patch<UserProfile>(
    "/profile/appearance/",
    payload
  );
  return data;
}

// ---------------------------------------------------------------------------
// PATCH /api/profile/preferences/
// ---------------------------------------------------------------------------

export async function updatePreferences(
  payload: PreferencesPayload
): Promise<UserProfile> {
  const { data } = await api.patch<UserProfile>(
    "/profile/preferences/",
    payload
  );
  return data;
}

// ---------------------------------------------------------------------------
// PATCH /api/profile/colors/
//
// Dedicated endpoint for syncing only semantic colors.
// Called by ColorSettingsPanel:
//   • On preset switch → sends the full preset palette immediately.
//   • On individual swatch change → debounced 800ms to avoid flooding.
//
// Returns { semantic_colors, profile } — the store hydrates from `profile`.
// ---------------------------------------------------------------------------

export async function updateSemanticColors(
  payload: SemanticColorsPayload
): Promise<{ semantic_colors: UserProfile["semantic_colors"]; profile: UserProfile }> {
  const { data } = await api.patch<{
    semantic_colors: UserProfile["semantic_colors"];
    profile: UserProfile;
  }>("/profile/colors/", payload);
  return data;
}

// ---------------------------------------------------------------------------
// POST /api/profile/colors/reset/
// Resets to DEFAULT_SEMANTIC_COLORS on the server.
// ---------------------------------------------------------------------------

export async function resetSemanticColors(): Promise<{
  semantic_colors: UserProfile["semantic_colors"];
  profile: UserProfile;
}> {
  const { data } = await api.post<{
    semantic_colors: UserProfile["semantic_colors"];
    profile: UserProfile;
  }>("/profile/colors/reset/");
  return data;
}