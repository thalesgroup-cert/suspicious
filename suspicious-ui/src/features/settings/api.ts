import { api } from "@/api/client";

export type SettingsSection =
  | "domains_allow"
  | "domains_deny"
  | "campaign_domains_allow"
  | "emails_files_allow"
  | "filetypes_allow"
  | "ciso_users"
  | "email_feeder"
  | "scoring";

export type ListItem = {
  id: string; // stable id (domain string, hash, username, etc.)
  value: string;
  created_at?: string;
};

export async function listItems(section: SettingsSection): Promise<ListItem[]> {
  const res = await api.get(`/settings/${section}/`);
  return res.data;
}

export async function addItems(section: SettingsSection, values: string[]): Promise<void> {
  await api.post(`/settings/${section}/`, { values });
}

export async function removeItem(section: SettingsSection, id: string): Promise<void> {
  await api.delete(`/settings/${section}/${encodeURIComponent(id)}/`);
}

export async function addFromFile(section: SettingsSection, file: File): Promise<void> {
  const fd = new FormData();
  fd.append("file", file);
  await api.post(`/settings/${section}/import/`, fd, {
    headers: { "Content-Type": "multipart/form-data" },
  });
}

/** Email feeder */
export type FeederStatus = { enabled: boolean };
export async function getFeederStatus(): Promise<FeederStatus> {
  const res = await api.get(`/settings/email_feeder/`);
  return res.data;
}
export async function setFeederStatus(enabled: boolean): Promise<void> {
  await api.post(`/settings/email_feeder/`, { enabled });
}

/** Scoring */
export type Analyzer = { id: string; name: string; weight: number };
export async function listAnalyzers(): Promise<Analyzer[]> {
  const res = await api.get(`/settings/scoring/`);
  return res.data;
}
export async function updateAnalyzerWeight(id: string, weight: number): Promise<void> {
  await api.post(`/settings/scoring/${encodeURIComponent(id)}/`, { weight });
}
