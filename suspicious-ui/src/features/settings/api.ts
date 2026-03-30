import { api } from "@/api/client";

export type SettingsSection =
  | "domains_allow"
  | "domains_deny"
  | "campaign_domains_allow"
  | "emails_files_allow"
  | "filetypes_allow"
  | "ciso_users"
  | "email_feeder"
  | "scoring"
  | "watcher_legit_domains"
  | "watcher_monitored_domains";

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

/**
 * Sections that are editable from the frontend.
 * Watcher sections are intentionally excluded because they are read-only.
 */
export type EditableListSection =
  | "domains_allow"
  | "domains_deny"
  | "campaign_domains_allow"
  | "emails_files_allow"
  | "filetypes_allow";

/**
 * Structured response from POST /settings/list/<section>/.
 *
 * created           — IDs of newly created entries
 * duplicates        — values that already existed in this list (skipped)
 * watcher_conflicts — values already present in the paired Watcher list
 *                     (legit for allow, monitored for deny) — no action needed
 */
export type AddItemsResult = {
  created: (string | number)[];
  duplicates: string[];
  watcher_conflicts: string[];
};

type ListResponseSection =
  | "domains_allow"
  | "domains_deny"
  | "campaign_domains_allow"
  | "emails_files_allow"
  | "filetypes_allow"
  | "watcher_legit_domains"
  | "watcher_monitored_domains";

type SectionResponseMap = {
  domains_allow: ListItem[];
  domains_deny: ListItem[];
  campaign_domains_allow: ListItem[];
  emails_files_allow: ListItem[];
  filetypes_allow: ListItem[];
  watcher_legit_domains: ListItem[];
  watcher_monitored_domains: ListItem[];
  ciso_users: CisoUser[];
};

export async function listItems<T extends keyof SectionResponseMap>(
  section: T
): Promise<SectionResponseMap[T]> {
  const res = await api.get(`/settings/list/${section}/`);
  return res.data;
}

export async function addItems(
  section: EditableListSection,
  values: string[]
): Promise<AddItemsResult> {
  const res = await api.post<AddItemsResult>(`/settings/list/${section}/`, { values });
  return res.data;
}

export async function removeItem(
  section: EditableListSection,
  id: string
) {
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

export async function addFromFile(
  section: EditableListSection,
  file: File
): Promise<AddItemsResult> {
  const text = await file.text();
  const values = text
    .split(/[\r\n,;]+/g)
    .map((v) => v.trim())
    .filter(Boolean);

  return addItems(section, values);
}