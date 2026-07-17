import { api } from "@/api/client";

export type ClassificationCounts = {
  SAFE: number;
  UNWANTED: number;
  DANGEROUS: number;
};

export type PcaPoint = {
  x: number;
  y: number;
  label: string;
  suspicious_case_id?: string | null;
  mail_subject?: string | null;
  sourceRefs?: string[];
};

export type PcaResponse = {
  points: PcaPoint[];
  explained_variance: [number, number];
};

type MailVolumeCampaign = {
  name: string;
  start: string;
  end: string;
};

export type MailVolumeResponse = {
  dates: string[];
  non_danger: number[];
  dangerous: number[];
  campaigns: MailVolumeCampaign[];
};

function toNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export async function getClassificationCounts(): Promise<ClassificationCounts> {
  const res = await api.get("/campaigns/classification-counts/");
  const data = res.data ?? {};

  return {
    SAFE:      toNumber(data.SAFE),
    UNWANTED:  toNumber(data.UNWANTED),
    DANGEROUS: toNumber(data.DANGEROUS),
  };
}

export async function getPca(limit = 1500): Promise<PcaResponse> {
  const res = await api.get("/campaigns/pca/", { params: { limit } });
  const data = res.data ?? {};

  return {
    explained_variance: [
      toNumber(data?.explained_variance?.[0]),
      toNumber(data?.explained_variance?.[1]),
    ],
    points: Array.isArray(data?.points)
      ? data.points.map((p: any) => ({
          x:     toNumber(p?.x),
          y:     toNumber(p?.y),
          label: typeof p?.label === "string" ? p.label : "UNKNOWN",
          suspicious_case_id:
            typeof p?.suspicious_case_id === "string" ? p.suspicious_case_id : null,
          mail_subject:
            typeof p?.mail_subject === "string" ? p.mail_subject : null,
          sourceRefs: Array.isArray(p?.sourceRefs)
            ? p.sourceRefs.filter((x: unknown): x is string => typeof x === "string")
            : [],
        }))
      : [],
  };
}

export async function getMailVolume(): Promise<MailVolumeResponse> {
  const res = await api.get("/campaigns/mail-volume/");
  const data = res.data ?? {};

  return {
    dates: Array.isArray(data?.dates)
      ? data.dates.filter((x: unknown): x is string => typeof x === "string")
      : [],
    non_danger: Array.isArray(data?.non_danger)
      ? data.non_danger.map((x: unknown) => toNumber(x))
      : [],
    dangerous: Array.isArray(data?.dangerous)
      ? data.dangerous.map((x: unknown) => toNumber(x))
      : [],
    campaigns: Array.isArray(data?.campaigns)
      ? data.campaigns
          .map((c: any) => ({
            name:  typeof c?.name  === "string" ? c.name  : "Campaign",
            start: typeof c?.start === "string" ? c.start : "",
            end:   typeof c?.end   === "string" ? c.end   : "",
          }))
          .filter((c: MailVolumeCampaign) => !!c.start && !!c.end)
      : [],
  };
}