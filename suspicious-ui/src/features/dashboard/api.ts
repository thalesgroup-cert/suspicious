import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";

export type DangerKey =
  | "failure"
  | "safe"
  | "inconclusive"
  | "suspicious"
  | "dangerous";

export type DashboardSummary = {
  month: number;
  year: number;
  scope: string;
  kpis: {
    new_users: number;
    total_reporters: number;
    total_cases: number;
  };
  danger_counts: Record<DangerKey, number>;
  top_prefixes: Array<{ label: string; value: number }>;
};

export type GetDashboardSummaryParams = {
  month: number;
  year: number;
  scope?: string;
};

function toNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function normalizeDashboardSummary(data: any): DashboardSummary {
  return {
    month: toNumber(data?.month),
    year: toNumber(data?.year),
    scope: typeof data?.scope === "string" ? data.scope : "ALL",
    kpis: {
      new_users: toNumber(data?.kpis?.new_users),
      total_reporters: toNumber(data?.kpis?.total_reporters),
      total_cases: toNumber(data?.kpis?.total_cases),
    },
    danger_counts: {
      failure: toNumber(data?.danger_counts?.failure),
      safe: toNumber(data?.danger_counts?.safe),
      inconclusive: toNumber(data?.danger_counts?.inconclusive),
      suspicious: toNumber(data?.danger_counts?.suspicious),
      dangerous: toNumber(data?.danger_counts?.dangerous),
    },
    top_prefixes: Array.isArray(data?.top_prefixes)
      ? data.top_prefixes
          .map((item: any) => ({
            label: typeof item?.label === "string" ? item.label : "",
            value: toNumber(item?.value),
          }))
          .filter((item: { label: string; value: number }) => item.label.length > 0)
      : [],
  };
}

export async function getDashboardSummary(
  params: GetDashboardSummaryParams
): Promise<DashboardSummary> {
  const res = await api.get(endpoints.dashboardSummary, { params });
  return normalizeDashboardSummary(res.data);
}