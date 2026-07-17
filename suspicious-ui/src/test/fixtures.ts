import type { Me } from "@/api/auth";
import type { DashboardSummary } from "@/features/dashboard/api";
import type {
  ClassificationCounts,
  PcaResponse,
  MailVolumeResponse,
} from "@/features/campaigns/api";
import type { UserProfile } from "@/features/profile/api";

export const fixtureMe: Me = {
  id: 1,
  username: "alice",
  email: "alice@example.com",
  first_name: "Alice",
  last_name: "Smith",
  groups: ["CERT"],
  ciso_scope: undefined,
  semantic_colors: undefined,
  theme: undefined,
  auto_seasonal: false,
};

export const fixtureMeSuperuser: Me = {
  ...fixtureMe,
  username: "admin",
  groups: ["CERT", "Admin"],
};

export const fixtureDashboardSummary: DashboardSummary = {
  month: 5,
  year: 2026,
  scope: "ALL",
  kpis: {
    new_users: 4,
    total_reporters: 128,
    total_cases: 512,
  },
  danger_counts: {
    failure: 1,
    safe: 200,
    inconclusive: 80,
    suspicious: 150,
    dangerous: 60,
    malicious: 21,
  },
  top_prefixes: [
    { label: "phishing-corp", value: 17 },
    { label: "spoof-it", value: 9 },
  ],
};

export const fixtureClassificationCounts: ClassificationCounts = {
  SAFE: 200,
  UNWANTED: 50,
  DANGEROUS: 30,
};

export const fixturePca: PcaResponse = {
  explained_variance: [0.62, 0.28],
  points: [
    { x: 0.1, y: 0.2, label: "SAFE", suspicious_case_id: "1", mail_subject: "Bonjour", sourceRefs: [] },
    { x: 0.5, y: -0.3, label: "DANGEROUS", suspicious_case_id: "2", mail_subject: "URGENT", sourceRefs: [] },
  ],
};

export const fixtureMailVolume: MailVolumeResponse = {
  dates: ["2026-05-15", "2026-05-16", "2026-05-17"],
  non_danger: [10, 12, 8],
  dangerous: [1, 3, 0],
  campaigns: [{ name: "Test campaign", start: "2026-05-15", end: "2026-05-17" }],
};

export const fixtureProfile: UserProfile = {
  id: 1,
  function: "Analyst",
  gbu: "Cyber",
  country: "FR",
  region: "EU",
  wants_acknowledgement: true,
  wants_results: true,
  theme: "graphite",
  auto_seasonal: false,
  semantic_colors: {
    result: {
      safe: { main: "#1b8f4f" },
      suspicious: { main: "#d97706" },
      dangerous: { main: "#dc2626" },
      inconclusive: { main: "#6b7280" },
    },
    status: {
      done: { main: "#1b8f4f" },
      in_progress: { main: "#2563eb" },
      new: { main: "#7c3aed" },
      failure: { main: "#dc2626" },
      challenged: { main: "#f59e0b" },
      unknown: { main: "#6b7280" },
    },
  },
  creation_date: "2026-01-01T00:00:00Z",
  last_update: "2026-05-01T00:00:00Z",
};

export const fixtureSubmissionsList = {
  count: 2,
  next: null,
  previous: null,
  results: [
    {
      id: 101,
      status: "DONE",
      artifact: "phish@example.com",
      created_at: "2026-05-17T10:00:00Z",
      tests_done: 5,
      type: "MAIL",
      result: "DANGEROUS",
      is_challengeable: false,
      is_challenged: false,
      mail_preview_url: null,
    },
    {
      id: 102,
      status: "ON_GOING",
      artifact: "https://benign.example.org",
      created_at: "2026-05-17T11:00:00Z",
      tests_done: 1,
      type: "URL",
      result: "INCONCLUSIVE",
      is_challengeable: false,
      is_challenged: false,
      mail_preview_url: null,
    },
  ],
};

export const fixtureSettingsList = [
  { id: "1", value: "thales.com", created_at: "2026-01-01T00:00:00Z" },
  { id: "2", value: "thalesgroup.com", created_at: "2026-01-02T00:00:00Z" },
];

export const fixtureFeederStatus = { enabled: true };

export const fixtureAnalyzers = [
  { id: 1, name: "VirusTotal_Get", weight: 1, analyzer_cortex_id: "vt", is_active: true },
  { id: 2, name: "AbuseIPDB", weight: 2, analyzer_cortex_id: "abuse", is_active: true },
];
