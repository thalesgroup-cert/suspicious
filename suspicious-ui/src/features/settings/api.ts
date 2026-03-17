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
  id: string;
  value: string;
  created_at?: string;
};

export type CisoUser = {
  id: string | number;
  username: string;
  email?: string;
  function?: string;
  gbu?: string;
  country?: string;
  region?: string;
  scope?: string;
};

export type Analyzer = {
  id: number;
  name: string;
  weight: number;
  analyzer_cortex_id: string;
  is_active: boolean;
};

type ListSection =
  | "domains_allow"
  | "domains_deny"
  | "campaign_domains_allow"
  | "emails_files_allow"
  | "filetypes_allow";

type SectionResponseMap = {
  domains_allow: ListItem[];
  domains_deny: ListItem[];
  campaign_domains_allow: ListItem[];
  emails_files_allow: ListItem[];
  filetypes_allow: ListItem[];
  ciso_users: CisoUser[];
};

export async function listItems<T extends keyof SectionResponseMap>(
  section: T
): Promise<SectionResponseMap[T]> {
  const res = await api.get(`/settings/list/${section}/`);
  return res.data;
}

export async function addItems(section: ListSection, values: string[]) {
  const res = await api.post(`/settings/list/${section}/`, { values });
  return res.data;
}

export async function removeItem(section: ListSection, id: string) {
  const res = await api.delete(`/settings/list/${section}/${id}/`);
  return res.data;
}

export async function getFeederStatus(): Promise<{ enabled: boolean }> {
  const res = await api.get(`/settings/email-feeder/`);
  return res.data;
}

export async function setFeederStatus(
  enabled: boolean
): Promise<{ enabled: boolean }> {
  const res = await api.patch(`/settings/email-feeder/`, { enabled });
  return res.data;
}

export async function listAnalyzers(): Promise<Analyzer[]> {
  const res = await api.get(`/settings/analyzers/`);
  return res.data;
}

export async function updateAnalyzerWeight(id: number, weight: number) {
  const res = await api.patch(`/settings/analyzers/${id}/`, { weight });
  return res.data;
}

export async function addFromFile(section: ListSection, file: File) {
  const text = await file.text();
  const values = text
    .split(/[\r\n,;]+/g)
    .map((v) => v.trim())
    .filter(Boolean);

  return addItems(section, values);
}