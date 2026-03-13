// src/features/investigation/api.ts
import { api } from "@/api/client";

export type InvestigationStatus =
  | "NEW"
  | "IN_PROGRESS"
  | "DONE"
  | "CHALLENGED"
  | "FAILED"
  | "REJECTED"
  | "UNKNOWN";

export type InvestigationType =
  | "FILE"
  | "MAIL"
  | "URL"
  | "IP"
  | "HASH"
  | "UNKNOWN";

export type InvestigationResult =
  | "SAFE"
  | "INCONCLUSIVE"
  | "UNCHALLENGED"
  | "ALLOW_LISTED"
  | "FAILURE"
  | "SUSPICIOUS"
  | "DANGEROUS"
  | "UNKNOWN";

export type InvestigationRow = {
  id: number;
  reporter_email?: string;
  status: InvestigationStatus;
  info: string;
  artifact?: string;
  created_at: string;
  tests_done: number;
  type: InvestigationType;
  result: InvestigationResult | string;
  is_challengeable?: boolean;
  is_challenged?: boolean;
};

export type InvestigationAnalyzerTarget = {
  kind: string;
  id: number | string | null;
  value: string | null;
};

export type InvestigationAnalyzerReport = {
  id: number;
  cortex_job_id?: string;
  type?: string;
  status?: string;
  analyzer_name?: string;
  analyzer_id?: string;
  level?: string;
  confidence?: number;
  score?: number;
  category?: string | null;
  categories?: string[];
  report_summary?: unknown;
  report_taxonomy?: unknown;
  report_full?: unknown;
  target?: InvestigationAnalyzerTarget | null;
  created_at?: string;
};

export type InvestigationDetails = {
  id: number;
  reporter_email?: string;
  status: InvestigationStatus;
  info: string;
  artifact?: string;
  created_at: string;
  tests_done: number;
  type: InvestigationType;
  result: InvestigationResult | string;
  is_challengeable?: boolean;
  is_challenged?: boolean;
  raw?: unknown;
  analyzer_reports?: InvestigationAnalyzerReport[];
  case_infos?: {
    id?: number;
    score?: number | null;
    confidence?: number | null;
    results?: string | null;
    classification?: string | null;
    finalScore?: number | null;
    finalConfidence?: number | null;
    resultsAI?: string | null;
    scoreAI?: number | null;
    confidenceAI?: number | null;
    categoryAI?: string | null;
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

export type InvestigationListResponse = {
  items: InvestigationRow[];
};

type InvestigationListApiResponse =
  | InvestigationRow[]
  | {
      items?: InvestigationRow[];
      results?: InvestigationRow[];
      count?: number;
    };

type EditGlobalCasePayload = {
  score: number;
  confidence: number;
  classification: string;
};

function normalizeStatus(value: unknown): InvestigationStatus {
  const v = String(value ?? "").toUpperCase();

  if (v === "NEW") return "NEW";
  if (v === "IN_PROGRESS") return "IN_PROGRESS";
  if (v === "DONE") return "DONE";
  if (v === "CHALLENGED") return "CHALLENGED";
  if (v === "FAILED") return "FAILED";
  if (v === "REJECTED") return "REJECTED";

  return "UNKNOWN";
}

function normalizeType(value: unknown): InvestigationType {
  const v = String(value ?? "").toUpperCase();

  if (v === "FILE") return "FILE";
  if (v === "MAIL") return "MAIL";
  if (v === "URL") return "URL";
  if (v === "IP") return "IP";
  if (v === "HASH") return "HASH";

  return "UNKNOWN";
}

function normalizeResult(value: unknown): InvestigationResult | string {
  const v = String(value ?? "").toUpperCase();

  if (v === "SAFE") return "SAFE";
  if (v === "INCONCLUSIVE") return "INCONCLUSIVE";
  if (v === "UNCHALLENGED") return "UNCHALLENGED";
  if (v === "ALLOW_LISTED") return "ALLOW_LISTED";
  if (v === "FAILURE") return "FAILURE";
  if (v === "SUSPICIOUS") return "SUSPICIOUS";
  if (v === "DANGEROUS") return "DANGEROUS";

  return v || "UNKNOWN";
}

function normalizeRow(row: Partial<InvestigationRow> & Record<string, unknown>): InvestigationRow {
  return {
    id: Number(row.id ?? 0),
    reporter_email: typeof row.reporter_email === "string" ? row.reporter_email : "",
    status: normalizeStatus(row.status),
    info:
      typeof row.info === "string"
        ? row.info
        : typeof row.artifact === "string"
        ? row.artifact
        : "",
    artifact: typeof row.artifact === "string" ? row.artifact : "",
    created_at:
      typeof row.created_at === "string"
        ? row.created_at
        : new Date().toISOString(),
    tests_done:
      typeof row.tests_done === "number"
        ? row.tests_done
        : Number(row.tests_done ?? 0),
    type: normalizeType(row.type),
    result: normalizeResult(row.result),
    is_challengeable:
      typeof row.is_challengeable === "boolean" ? row.is_challengeable : false,
    is_challenged:
      typeof row.is_challenged === "boolean" ? row.is_challenged : false,
  };
}

function normalizeAnalyzerReport(
  report: Partial<InvestigationAnalyzerReport> & Record<string, unknown>,
): InvestigationAnalyzerReport {
  return {
    id: Number(report.id ?? 0),
    cortex_job_id:
      typeof report.cortex_job_id === "string" ? report.cortex_job_id : "",
    type: typeof report.type === "string" ? report.type : "",
    status: typeof report.status === "string" ? report.status : "",
    analyzer_name:
      typeof report.analyzer_name === "string" ? report.analyzer_name : "",
    analyzer_id:
      typeof report.analyzer_id === "string" ? report.analyzer_id : "",
    level: typeof report.level === "string" ? report.level : "",
    confidence:
      typeof report.confidence === "number"
        ? report.confidence
        : Number(report.confidence ?? 0),
    score:
      typeof report.score === "number" ? report.score : Number(report.score ?? 0),
    category: typeof report.category === "string" ? report.category : null,
    categories: Array.isArray(report.categories)
      ? report.categories.map((x) => String(x))
      : [],
    report_summary: report.report_summary,
    report_taxonomy: report.report_taxonomy,
    report_full: report.report_full,
    target:
      report.target && typeof report.target === "object"
        ? (report.target as InvestigationAnalyzerTarget)
        : null,
    created_at:
      typeof report.created_at === "string" ? report.created_at : undefined,
  };
}

function normalizeDetails(
  data: Partial<InvestigationDetails> & Record<string, unknown>,
): InvestigationDetails {
  const analyzerReportsRaw = Array.isArray(data.analyzer_reports)
    ? data.analyzer_reports
    : [];

  return {
    ...data,
    id: Number(data.id ?? 0),
    reporter_email: typeof data.reporter_email === "string" ? data.reporter_email : "",
    status: normalizeStatus(data.status),
    info:
      typeof data.info === "string"
        ? data.info
        : typeof data.artifact === "string"
        ? data.artifact
        : "",
    artifact: typeof data.artifact === "string" ? data.artifact : "",
    created_at:
      typeof data.created_at === "string"
        ? data.created_at
        : new Date().toISOString(),
    tests_done:
      typeof data.tests_done === "number"
        ? data.tests_done
        : Number(data.tests_done ?? 0),
    type: normalizeType(data.type),
    result: normalizeResult(data.result),
    is_challengeable:
      typeof data.is_challengeable === "boolean" ? data.is_challengeable : false,
    is_challenged:
      typeof data.is_challenged === "boolean" ? data.is_challenged : false,
    analyzer_reports: analyzerReportsRaw.map((r) =>
      normalizeAnalyzerReport(r as Record<string, unknown>),
    ),
    case_infos:
      data.case_infos && typeof data.case_infos === "object"
        ? (data.case_infos as InvestigationDetails["case_infos"])
        : undefined,
    raw: data.raw ?? data,
  };
}

export async function getAllInvestigations(): Promise<InvestigationListResponse> {
  const res = await api.get("/investigations/");
  const data = res.data as InvestigationListApiResponse;

  if (Array.isArray(data)) {
    return { items: data.map((row) => normalizeRow(row)) };
  }

  const items = Array.isArray(data.items)
    ? data.items
    : Array.isArray(data.results)
    ? data.results
    : [];

  return {
    items: items.map((row) => normalizeRow(row)),
  };
}

export async function getInvestigationDetails(
  caseId: number,
): Promise<InvestigationDetails> {
  const res = await api.get(`/investigations/${caseId}/`);
  return normalizeDetails(res.data as Record<string, unknown>);
}

export async function editGlobalCase(
  caseId: number,
  score: number,
  confidence: number,
  classification: string,
): Promise<InvestigationDetails> {
  const payload: EditGlobalCasePayload = {
    score,
    confidence,
    classification,
  };

  const res = await api.patch(`/investigations/${caseId}/edit-global/`, payload);
  return normalizeDetails(res.data as Record<string, unknown>);
}