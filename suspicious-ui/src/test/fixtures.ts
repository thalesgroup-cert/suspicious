import type { Me } from "@/api/auth";
import type { DashboardSummary } from "@/features/dashboard/api";
import type {
  CampaignNeighbours,
  CampaignSummary,
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
  month: 10,
  year: 2026,
  scope: { key: "ALL", label: "Overall" },
  reports: 512,
  outcomes: { safe: 200, inconclusive: 80, suspicious: 150, dangerous: 60, failure: 1 },
  in_progress: 21,
  by_type: { MAIL: 400, FILE: 50, URL: 40, IP: 10, HASH: 5, IOC: 5, UNKNOWN: 2 },
  reporters: 128,
  new_users: 4,
  previous: {
    reports: 480,
    outcomes: { safe: 190, inconclusive: 70, suspicious: 140, dangerous: 55, failure: 2 },
  },
  trend: [
    { week_start: "2026-09-28", reports: 90 },
    { week_start: "2026-10-05", reports: 130 },
  ],
  top_reporters: [
    { label: "phishing-corp", value: 17 },
    { label: "spoof-it", value: 9 },
  ],
};

export const fixturePca: PcaResponse = {
  explained_variance: [0.24, 0.15, 0.09],
  points: [
    { x: 0.1, y: 0.2, z: 0.05, label: "SAFE", suspicious_case_id: "1", mail_subject: "Bonjour", sourceRefs: [], date: "2026-10-10" },
    { x: 0.5, y: -0.3, z: -0.1, label: "DANGEROUS", suspicious_case_id: "2", mail_subject: "URGENT", sourceRefs: [], date: "2026-10-12" },
  ],
};

export const fixtureMailVolume: MailVolumeResponse = {
  dates: ["2026-10-11", "2026-10-12", "2026-10-13"],
  non_danger: [10, 12, 8],
  dangerous: [1, 3, 0],
};

export const fixtureCampaignSummary: CampaignSummary = {
  days: 15,
  period: { start: "2026-09-29", end: "2026-10-13" },
  messages: 34,
  previous_messages: 20,
  dangerous: 4,
  previous_dangerous: 1,
  dangerous_share: 4 / 34,
  previous_dangerous_share: 1 / 20,
  peak_day: { date: "2026-10-12", count: 15 },
  mix: { SAFE: 20, UNWANTED: 6, SUSPICIOUS: 2, DANGEROUS: 4 },
  unclassified: 2,
  campaigns: [
    {
      name: "invoice-relay.example, cdn-pay.example, login-portal.example",
      first_seen: "2026-10-11T08:00:00Z",
      last_seen: "2026-10-12T09:00:00Z",
      messages: 12,
      dangerous: 3,
      dangerous_share: 0.25,
      sample_subject: "Your invoice is overdue",
      case_ids: ["41", "40"],
      active: true,
    },
    {
      name: "newsletter.example",
      first_seen: "2026-10-01T10:00:00Z",
      last_seen: "2026-10-03T10:00:00Z",
      messages: 5,
      dangerous: 0,
      dangerous_share: 0,
      sample_subject: "Weekly digest",
      case_ids: [],
      active: false,
    },
  ],
  active_window_hours: 48,
  active_campaigns: 1,
  largest_campaign: { name: "invoice-relay.example, cdn-pay.example, login-portal.example", messages: 12 },
};

export const fixtureNeighbours: CampaignNeighbours = {
  k: 10,
  bad_share_threshold: 0.6,
  novelty_percentile: 95,
  novel_window_days: 7,
  near_known_bad: [
    {
      suspicious_case_id: "17",
      mail_subject: "Reset your password",
      label: "SAFE",
      date: "2026-10-09",
      score: 0.8,
      nearest_dangerous_case_id: "2",
      nearest_dangerous_similarity: 0.62,
    },
  ],
  novel: [
    {
      suspicious_case_id: "33",
      mail_subject: "Unusual parcel notice",
      label: "UNWANTED",
      date: "2026-10-12",
      score: 0.41,
      nearest_dangerous_case_id: null,
      nearest_dangerous_similarity: null,
    },
  ],
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
