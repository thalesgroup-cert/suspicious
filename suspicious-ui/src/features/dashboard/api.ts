import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";

export type DashboardSummary = {
  month: number;
  year: number;
  scope: string;
  kpis: {
    new_users: number;
    total_reporters: number;
    total_cases: number;
  };
  danger_counts: Record<
    "failure" | "safe" | "inconclusive" | "suspicious" | "dangerous" | "malicious",
    number
  >;
  top_prefixes: Array<{ label: string; value: number }>;
};

export async function getDashboardSummary(params: {
  month: number;
  year: number;
  scope?: string;
}): Promise<DashboardSummary> {
  const res = await api.get(endpoints.dashboardSummary, { params });
  return res.data;
}
