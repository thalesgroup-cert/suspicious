import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";

const OUTCOME_KEYS = ["safe", "inconclusive", "suspicious", "dangerous", "failure"] as const;
const TYPE_KEYS = ["MAIL", "FILE", "URL", "IP", "HASH", "IOC", "UNKNOWN"] as const;
const DANGER_KEYS = [...OUTCOME_KEYS, "malicious"] as const;

export type Outcomes = Record<(typeof OUTCOME_KEYS)[number], number>;
export type ByType = Record<(typeof TYPE_KEYS)[number], number>;
export type ScopeOption = { key: string; label: string };
export type LabelValue = { label: string; value: number };

export type DashboardSummary = {
  month: number;
  year: number;
  scope: ScopeOption;
  /** Cases created in the month, in the scope. */
  reports: number;
  /** Finished cases only (a verdict exists). */
  outcomes: Outcomes;
  in_progress: number;
  by_type: ByType;
  reporters: number;
  new_users: number;
  previous: { reports: number; outcomes: Outcomes };
  trend: Array<{ week_start: string; reports: number }>;
  /** Reporter names: only for CERT/Admin/CISO, null for everyone else. */
  top_reporters: LabelValue[] | null;
  // Legacy keys, read by the current panels until Task 3 replaces them.
  kpis?: { new_users: number; total_reporters: number; total_cases: number };
  danger_counts?: Record<(typeof DANGER_KEYS)[number], number>;
  top_prefixes?: LabelValue[];
};

export type DashboardScopes = { default: string; options: ScopeOption[] };

export type GetDashboardSummaryParams = {
  month: number;
  year: number;
  scope?: string;
};

type Raw = Record<string, unknown> | null | undefined;

function num(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function counts<K extends string>(keys: readonly K[], raw: unknown): Record<K, number> {
  const src = (raw ?? {}) as Record<string, unknown>;
  return Object.fromEntries(keys.map((k) => [k, num(src[k])])) as Record<K, number>;
}

function labelValues(raw: unknown): LabelValue[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((item) => ({ label: typeof item?.label === "string" ? item.label : "", value: num(item?.value) }))
    .filter((item) => item.label.length > 0);
}

function scopeOption(raw: unknown): ScopeOption | null {
  const o = raw as Raw;
  return typeof o?.key === "string" && typeof o?.label === "string" ? { key: o.key, label: o.label } : null;
}

const OVERALL: ScopeOption = { key: "ALL", label: "Overall" };

function normalizeDashboardSummary(data: Raw): DashboardSummary {
  const d = data ?? {};
  const previous = (d.previous ?? {}) as Raw;
  const trend = Array.isArray(d.trend) ? d.trend : [];
  return {
    month: num(d.month),
    year: num(d.year),
    scope: scopeOption(d.scope) ?? OVERALL,
    reports: num(d.reports),
    outcomes: counts(OUTCOME_KEYS, d.outcomes),
    in_progress: num(d.in_progress),
    by_type: counts(TYPE_KEYS, d.by_type),
    reporters: num(d.reporters),
    new_users: num(d.new_users),
    previous: { reports: num(previous?.reports), outcomes: counts(OUTCOME_KEYS, previous?.outcomes) },
    trend: trend
      .filter((p) => typeof p?.week_start === "string")
      .map((p) => ({ week_start: p.week_start as string, reports: num(p.reports) })),
    top_reporters: Array.isArray(d.top_reporters) ? labelValues(d.top_reporters) : null,
    kpis: counts(["new_users", "total_reporters", "total_cases"] as const, d.kpis),
    danger_counts: counts(DANGER_KEYS, d.danger_counts),
    top_prefixes: labelValues(d.top_prefixes),
  };
}

export async function getDashboardSummary(params: GetDashboardSummaryParams): Promise<DashboardSummary> {
  const res = await api.get(endpoints.dashboardSummary, { params });
  return normalizeDashboardSummary(res.data);
}

export async function getDashboardScopes(): Promise<DashboardScopes> {
  const res = await api.get(endpoints.dashboardScopes);
  const raw = (res.data ?? {}) as Raw;
  const options = (Array.isArray(raw?.options) ? raw.options : [])
    .map(scopeOption)
    .filter((o): o is ScopeOption => o !== null);
  if (options.length === 0) options.push(OVERALL);
  const fallback = options.some((o) => o.key === "ALL") ? "ALL" : options[0].key;
  const def = typeof raw?.default === "string" && options.some((o) => o.key === raw.default) ? raw.default : fallback;
  return { default: def, options };
}
