import { api } from "@/api/client";

export type ClassificationCounts = {
  SAFE: number;
  UNWANTED: number;
  DANGEROUS: number;
  SUSPICIOUS?: number;
  UNKNOWN?: number;
};

export type PcaPoint = {
  x: number;
  y: number;
  label: string; // SAFE/UNWANTED/DANGEROUS/...
  suspiciousCaseId?: string | number | null;
  sourceRefs?: string[]; // campaign refs
};

export type PcaResponse = {
  points: PcaPoint[];
  explained_variance?: [number, number];
};

export type CampaignRange = {
  name: string;
  start: string; // ISO date or datetime
  end: string;   // ISO date or datetime
};

export type MailVolumeResponse = {
  dates: string[]; // YYYY-MM-DD
  non_danger: number[];
  dangerous: number[];
  campaigns?: CampaignRange[];
};

export async function getClassificationCounts(): Promise<ClassificationCounts> {
  const res = await api.get("/dashboard/campaigns/classification-counts/");
  return res.data;
}

export async function getPca(limit = 1500): Promise<PcaResponse> {
  const res = await api.get(`/dashboard/campaigns/pca/?limit=${limit}`);
  return res.data;
}

export async function getMailVolume(): Promise<MailVolumeResponse> {
  const res = await api.get("/dashboard/campaigns/mail-volume/");
  return res.data;
}
