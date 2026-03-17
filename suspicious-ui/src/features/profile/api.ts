import { api } from "@/api/client";

export type UserProfile = {
  function?: string;
  gbu?: string;
  country?: string;
  region?: string;
  wants_acknowledgement: boolean;
  wants_results: boolean;
  theme: string;
  auto_seasonal: boolean;
};

export async function getProfile(): Promise<UserProfile> {
  const res = await api.get("/profile/");
  return res.data;
}

export async function updatePreferences(input: {
  wants_acknowledgement: boolean;
  wants_results: boolean;
}): Promise<UserProfile> {
  const res = await api.patch("/profile/preferences/", input);
  return res.data;
}

export async function updateAppearance(input: {
  theme: string;
  auto_seasonal?: boolean;
}): Promise<UserProfile> {
  const res = await api.patch("/profile/appearance/", input);
  return res.data;
}