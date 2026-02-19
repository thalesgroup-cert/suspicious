import { api } from "@/api/client";
import type { ThemeName } from "@/styles/themes";

export type UserProfile = {
  wants_acknowledgement: boolean;
  wants_results: boolean;
  theme: ThemeName | null;
};

export async function getProfile(): Promise<UserProfile> {
  const res = await api.get("/profile/me/");
  return res.data;
}

export async function updatePreferences(input: {
  wants_acknowledgement: boolean;
  wants_results: boolean;
}): Promise<UserProfile> {
  const res = await api.patch("/profile/me/preferences/", input);
  return res.data;
}

export async function updateAppearance(input: {
  theme: ThemeName;
}): Promise<UserProfile> {
  const res = await api.patch("/profile/me/appearance/", input);
  return res.data;
}
