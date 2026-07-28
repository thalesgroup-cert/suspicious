
import { api } from "@/api/client";
import type { ResultColors, StatusColors } from "@/styles/colorStore";
import type { AvatarConfig } from "@/features/profile/avatar";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type UserProfile = {
  id:                   number;
  function:             string;
  gbu:                  string;
  country:              string;
  region:               string;
  scope?:               string;
  wants_acknowledgement: boolean;
  wants_results:         boolean;
  theme:                 string;
  auto_seasonal:         boolean;
  avatar?:               AvatarConfig;
  tour_completed?:       boolean;
  sidebar_pinned?:       boolean;
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
  avatar?:          AvatarConfig;
  semantic_colors?: {
    result?: Partial<ResultColors>;
    status?: Partial<StatusColors>;
  };
};

export type PreferencesPayload = {
  wants_acknowledgement?: boolean;
  wants_results?:         boolean;
  tour_completed?:        boolean;
  sidebar_pinned?:        boolean;
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
// POST /api/profile/avatar/upload/
// ---------------------------------------------------------------------------

export async function uploadAvatar(file: File): Promise<UserProfile> {
  const form = new FormData();
  form.append("avatar", file);
  const { data } = await api.post<UserProfile>("/profile/avatar/upload/", form);
  return data;
}

// ---------------------------------------------------------------------------
// PATCH /api/profile/appearance/
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