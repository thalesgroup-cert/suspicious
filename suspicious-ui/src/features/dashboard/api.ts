import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";

type DangerKey =
  | "failure"
  | "safe"
  | "inconclusive"
  | "suspicious"
  | "dangerous"
  | "malicious";

export type DashboardSummary = {
  month: number;
  year: number;
  scope: string;
  kpis: {
    new_users: number;
    total_reporters: number;
    total_cases: number;
    challenged_cases: number;
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
      challenged_cases: toNumber(data?.kpis?.challenged_cases),
    },
    danger_counts: {
      failure: toNumber(data?.danger_counts?.failure),
      safe: toNumber(data?.danger_counts?.safe),
      inconclusive: toNumber(data?.danger_counts?.inconclusive),
      suspicious: toNumber(data?.danger_counts?.suspicious),
      dangerous: toNumber(data?.danger_counts?.dangerous),
      malicious: toNumber(data?.danger_counts?.malicious),
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

export type AiModelRun = {
  id: number;
  run_timestamp: string;
  dataset_dir: string;
  label: string;
  model_name: string;
  f1_score: number;
  accuracy: number;
  // Scored against a fixed held-out benchmark (retrain model monthly/
  // golden_set.py) instead of a random test split that's a different slice
  // of the dataset every cycle - null until a golden set exists and has
  // coverage for this label, but the only apples-to-apples trend once it does.
  f1_score_golden: number | null;
  accuracy_golden: number | null;
  promoted: boolean;
  creation_date: string;
};

function normalizeAiModelRun(item: any): AiModelRun {
  return {
    id: toNumber(item?.id),
    run_timestamp: typeof item?.run_timestamp === "string" ? item.run_timestamp : "",
    dataset_dir: typeof item?.dataset_dir === "string" ? item.dataset_dir : "",
    label: typeof item?.label === "string" ? item.label : "",
    model_name: typeof item?.model_name === "string" ? item.model_name : "",
    f1_score: toNumber(item?.f1_score),
    accuracy: toNumber(item?.accuracy),
    f1_score_golden: typeof item?.f1_score_golden === "number" ? item.f1_score_golden : null,
    accuracy_golden: typeof item?.accuracy_golden === "number" ? item.accuracy_golden : null,
    promoted: Boolean(item?.promoted),
    creation_date: typeof item?.creation_date === "string" ? item.creation_date : "",
  };
}

// Most-recent-first, capped to enough rows for a handful of runs across the
// 5 sub-models (backend orders by -run_timestamp already).
export async function getAiModelRuns(limit = 50): Promise<AiModelRun[]> {
  const res = await api.get(endpoints.aiModelRuns, { params: { limit } });
  const results = Array.isArray(res.data?.results) ? res.data.results : res.data;
  return Array.isArray(results) ? results.map(normalizeAiModelRun) : [];
}