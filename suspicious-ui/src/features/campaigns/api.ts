import { api } from "@/api/client";

// Shapes mirror Suspicious/Suspicious/api/serializers/campaigns.py.

export type ClassificationCounts = {
  SAFE: number;
  UNWANTED: number;
  SUSPICIOUS: number;
  DANGEROUS: number;
};

export type PcaPoint = {
  x: number;
  y: number;
  z: number;
  label: string;
  suspicious_case_id: string | null;
  mail_subject: string | null;
  sourceRefs: string[];
  /** UTC day the mail was sent, "YYYY-MM-DD". */
  date: string | null;
};

export type PcaResponse = {
  points: PcaPoint[];
  /** 2 or 3 ratios, one per component. */
  explained_variance: number[];
};

export type MailVolumeResponse = {
  dates: string[];
  non_danger: number[];
  dangerous: number[];
};

export type CampaignRow = {
  name: string;
  /** Datetimes, within the period. */
  first_seen: string;
  last_seen: string;
  messages: number;
  dangerous: number;
  dangerous_share: number;
  sample_subject: string | null;
  /** Up to 20, most recent first. */
  case_ids: string[];
  active: boolean;
};

export type CampaignSummary = {
  days: number;
  period: { start: string; end: string };
  messages: number;
  previous_messages: number;
  dangerous: number;
  previous_dangerous: number;
  dangerous_share: number | null;
  previous_dangerous_share: number | null;
  peak_day: { date: string; count: number } | null;
  mix: ClassificationCounts;
  unclassified: number;
  campaigns: CampaignRow[];
  active_window_hours: number;
  active_campaigns: number;
  largest_campaign: { name: string; messages: number } | null;
};

export type NeighbourItem = {
  suspicious_case_id: string | null;
  mail_subject: string | null;
  label: string;
  date: string | null;
  score: number;
  nearest_dangerous_case_id: string | null;
  nearest_dangerous_similarity: number | null;
};

export type CampaignNeighbours = {
  k: number;
  bad_share_threshold: number;
  novelty_percentile: number;
  novel_window_days: number;
  near_known_bad: NeighbourItem[];
  novel: NeighbourItem[];
};

const num = (v: unknown, fallback = 0): number => (typeof v === "number" && Number.isFinite(v) ? v : fallback);
const numOrNull = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown, fallback = ""): string => (typeof v === "string" ? v : fallback);
const strOrNull = (v: unknown): string | null => (typeof v === "string" ? v : null);
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
const list = (v: unknown): any[] => (Array.isArray(v) ? v : []);

function counts(data: any): ClassificationCounts {
  return {
    SAFE: num(data?.SAFE),
    UNWANTED: num(data?.UNWANTED),
    SUSPICIOUS: num(data?.SUSPICIOUS),
    DANGEROUS: num(data?.DANGEROUS),
  };
}

export async function getPca(limit = 1500): Promise<PcaResponse> {
  const res = await api.get("/campaigns/pca/", { params: { limit } });
  const data = res.data ?? {};
  return {
    explained_variance: list(data.explained_variance).map((v) => num(v)),
    points: list(data.points).map((p) => ({
      x: num(p?.x),
      y: num(p?.y),
      z: num(p?.z),
      label: str(p?.label, "UNKNOWN"),
      suspicious_case_id: strOrNull(p?.suspicious_case_id),
      mail_subject: strOrNull(p?.mail_subject),
      sourceRefs: strings(p?.sourceRefs),
      date: strOrNull(p?.date),
    })),
  };
}

export async function getMailVolume(days = 15): Promise<MailVolumeResponse> {
  const res = await api.get("/campaigns/mail-volume/", { params: { days } });
  const data = res.data ?? {};
  return {
    dates: strings(data.dates),
    non_danger: list(data.non_danger).map((v) => num(v)),
    dangerous: list(data.dangerous).map((v) => num(v)),
  };
}

export async function getCampaignSummary(days = 15): Promise<CampaignSummary> {
  const res = await api.get("/campaigns/summary/", { params: { days } });
  const d = res.data ?? {};
  const peak = d.peak_day && typeof d.peak_day.date === "string" ? { date: d.peak_day.date, count: num(d.peak_day.count) } : null;
  const largest =
    d.largest_campaign && typeof d.largest_campaign.name === "string"
      ? { name: d.largest_campaign.name, messages: num(d.largest_campaign.messages) }
      : null;
  return {
    days: num(d.days, days),
    period: { start: str(d.period?.start), end: str(d.period?.end) },
    messages: num(d.messages),
    previous_messages: num(d.previous_messages),
    dangerous: num(d.dangerous),
    previous_dangerous: num(d.previous_dangerous),
    dangerous_share: numOrNull(d.dangerous_share),
    previous_dangerous_share: numOrNull(d.previous_dangerous_share),
    peak_day: peak,
    mix: counts(d.mix),
    unclassified: num(d.unclassified),
    campaigns: list(d.campaigns).map((c) => ({
      name: str(c?.name),
      first_seen: str(c?.first_seen),
      last_seen: str(c?.last_seen),
      messages: num(c?.messages),
      dangerous: num(c?.dangerous),
      dangerous_share: num(c?.dangerous_share),
      sample_subject: strOrNull(c?.sample_subject),
      case_ids: strings(c?.case_ids),
      active: c?.active === true,
    })),
    active_window_hours: num(d.active_window_hours),
    active_campaigns: num(d.active_campaigns),
    largest_campaign: largest,
  };
}

function neighbourItem(i: any): NeighbourItem {
  return {
    suspicious_case_id: strOrNull(i?.suspicious_case_id),
    mail_subject: strOrNull(i?.mail_subject),
    label: str(i?.label, "UNKNOWN"),
    date: strOrNull(i?.date),
    score: num(i?.score),
    nearest_dangerous_case_id: strOrNull(i?.nearest_dangerous_case_id),
    nearest_dangerous_similarity: numOrNull(i?.nearest_dangerous_similarity),
  };
}

export async function getNeighbours(limit = 1500): Promise<CampaignNeighbours> {
  const res = await api.get("/campaigns/neighbours/", { params: { limit } });
  const d = res.data ?? {};
  return {
    k: num(d.k),
    bad_share_threshold: num(d.bad_share_threshold),
    novelty_percentile: num(d.novelty_percentile),
    novel_window_days: num(d.novel_window_days),
    near_known_bad: list(d.near_known_bad).map(neighbourItem),
    novel: list(d.novel).map(neighbourItem),
  };
}
