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

type InvestigationSort =
  | "date_desc"
  | "date_asc"
  | "id_desc"
  | "id_asc";

type InvestigationRow = {
  id: number;
  reporter_email: string;
  status: InvestigationStatus;
  info: string;
  artifact: string;
  created_at: string;
  tests_done: number;
  type: InvestigationType;
  result: InvestigationResult | string;
  is_challengeable: boolean;
  is_challenged: boolean;
  /** Relative URL to the rendered .eml→png preview, or null when absent / not a mail. */
  mail_preview_url?: string | null;
};

type InvestigationAnalyzerTarget = {
  kind: string;
  id: number | string | null;
  value: string | null;
};

type InvestigationAnalyzerReport = {
  id: number;
  cortex_job_id: string;
  type: string;
  status: string;
  analyzer_name: string;
  analyzer_id: string;
  level: string;
  confidence: number | null;
  score: number | null;
  category: string | null;
  categories: string[];
  report_summary?: unknown;
  report_taxonomy?: unknown;
  report_full?: unknown;
  target: InvestigationAnalyzerTarget | null;
  created_at?: string;
};

type InvestigationCaseInfos = {
  id?: number;
  score?: number | null;
  confidence?: number | null;
  results?: string | null;
  classification?: string | null;
  final_score?: number | null;
  final_confidence?: number | null;
  results_ai?: string | null;
  score_ai?: number | null;
  confidence_ai?: number | null;
  category_ai?: string | null;
  [key: string]: unknown;
};

export type InvestigationDetails = {
  id: number;
  reporter_email: string;
  status: InvestigationStatus;
  info: string;
  artifact: string;
  created_at: string;
  tests_done: number;
  type: InvestigationType;
  result: InvestigationResult | string;
  is_challengeable: boolean;
  is_challenged: boolean;
  /** Relative URL to the rendered .eml→png preview, or null when absent / not a mail. */
  mail_preview_url?: string | null;
  raw?: unknown;
  analyzer_reports: InvestigationAnalyzerReport[];
  case_infos?: InvestigationCaseInfos;
  challenge_proposed_result?: "Safe" | "Dangerous" | "";
  challenge_reason?: string;
  reporter_context?: string;
  reporter_note?: string;
  is_allowlisted: boolean;
  is_denylisted: boolean;
  list_reason: string;
  [key: string]: unknown;
};

export type InvestigationListParams = {
  page?: number;
  pageSize?: number;
  search?: string;
  status?: InvestigationStatus | "ALL";
  type?: InvestigationType | "ALL";
  result?: InvestigationResult | "ALL";
  ordering?: string;
  from?: string;
  to?: string;
  sort?: InvestigationSort;
};

export type InvestigationListResponse = {
  count: number;
  next: string | null;
  previous: string | null;
  results: InvestigationRow[];
};

type EditGlobalCasePayload = {
  score: number;
  confidence: number;
  classification: string;
};

type InvestigationListApiResponse = {
  count?: unknown;
  next?: unknown;
  previous?: unknown;
  results?: unknown;
};

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}
function asNullableString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}
function asBoolean(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}
function asNumber(value: unknown, fallback = 0): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}
function asNullableNumber(value: unknown): number | null {
  if (value == null || value === "") return null;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}
function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item));
}
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeStatus(value: unknown): InvestigationStatus {
  switch (String(value ?? "").toUpperCase()) {
    case "NEW": return "NEW";
    case "IN_PROGRESS": return "IN_PROGRESS";
    case "DONE": return "DONE";
    case "CHALLENGED": return "CHALLENGED";
    case "FAILED": return "FAILED";
    case "REJECTED": return "REJECTED";
    default: return "UNKNOWN";
  }
}
function normalizeType(value: unknown): InvestigationType {
  switch (String(value ?? "").toUpperCase()) {
    case "FILE": return "FILE";
    case "MAIL": return "MAIL";
    case "URL": return "URL";
    case "IP": return "IP";
    case "HASH": return "HASH";
    default: return "UNKNOWN";
  }
}
function normalizeResult(value: unknown): InvestigationResult | string {
  switch (String(value ?? "").toUpperCase()) {
    case "SAFE": return "SAFE";
    case "INCONCLUSIVE": return "INCONCLUSIVE";
    case "UNCHALLENGED": return "UNCHALLENGED";
    case "ALLOW_LISTED": return "ALLOW_LISTED";
    case "FAILURE": return "FAILURE";
    case "SUSPICIOUS": return "SUSPICIOUS";
    case "DANGEROUS": return "DANGEROUS";
    default: return String(value ?? "").toUpperCase() || "UNKNOWN";
  }
}

function normalizeRow(input: unknown): InvestigationRow {
  const row = isObject(input) ? input : {};
  const artifact = asString(row.artifact);
  const info = asString(row.info, artifact);
  return {
    id: asNumber(row.id, 0),
    reporter_email: asString(row.reporter_email),
    status: normalizeStatus(row.status),
    info,
    artifact,
    created_at: asString(row.created_at, new Date().toISOString()),
    tests_done: asNumber(row.tests_done, 0),
    type: normalizeType(row.type),
    result: normalizeResult(row.result),
    is_challengeable: asBoolean(row.is_challengeable, false),
    is_challenged: asBoolean(row.is_challenged, false),
  };
}

function normalizeAnalyzerTarget(value: unknown): InvestigationAnalyzerTarget | null {
  if (!isObject(value)) return null;
  let normalizedId: string | number | null = null;
  if (typeof value.id === "number" || typeof value.id === "string") normalizedId = value.id;
  return {
    kind: asString(value.kind, "unknown"),
    id: normalizedId,
    value: typeof value.value === "string" ? value.value : null,
  };
}

function normalizeAnalyzerReport(input: unknown): InvestigationAnalyzerReport {
  const report = isObject(input) ? input : {};
  return {
    id: asNumber(report.id, 0),
    cortex_job_id: asString(report.cortex_job_id),
    type: asString(report.type),
    status: asString(report.status),
    analyzer_name: asString(report.analyzer_name),
    analyzer_id: asString(report.analyzer_id),
    level: asString(report.level),
    confidence: asNullableNumber(report.confidence),
    score: asNullableNumber(report.score),
    category: asNullableString(report.category),
    categories: asStringArray(report.categories),
    report_summary: report.report_summary,
    report_taxonomy: report.report_taxonomy,
    report_full: report.report_full,
    target: normalizeAnalyzerTarget(report.target),
    created_at: typeof report.created_at === "string" ? report.created_at : undefined,
  };
}

function normalizeCaseInfos(value: unknown): InvestigationCaseInfos | undefined {
  if (!isObject(value)) return undefined;
  return value as InvestigationCaseInfos;
}

function normalizeDetails(input: unknown): InvestigationDetails {
  const data = isObject(input) ? input : {};
  const artifact = asString(data.artifact);
  const info = asString(data.info, artifact);
  const analyzerReportsRaw = Array.isArray(data.analyzer_reports) ? data.analyzer_reports : [];
  return {
    ...data,
    id: asNumber(data.id, 0),
    reporter_email: asString(data.reporter_email),
    status: normalizeStatus(data.status),
    info,
    artifact,
    created_at: asString(data.created_at, new Date().toISOString()),
    tests_done: asNumber(data.tests_done, 0),
    type: normalizeType(data.type),
    result: normalizeResult(data.result),
    is_challengeable: asBoolean(data.is_challengeable, false),
    is_challenged: asBoolean(data.is_challenged, false),
    is_allowlisted: asBoolean(data.is_allowlisted, false),
    is_denylisted: asBoolean(data.is_denylisted, false),
    list_reason: asString(data.list_reason),
    analyzer_reports: analyzerReportsRaw.map(normalizeAnalyzerReport),
    case_infos: normalizeCaseInfos(data.case_infos),
    raw: data.raw ?? data,
  };
}

function mapSort(sort: InvestigationListParams["sort"]): string {
  switch (sort) {
    case "date_asc": return "creation_date";
    case "id_desc": return "-id";
    case "id_asc": return "id";
    case "date_desc":
    default: return "-creation_date";
  }
}

export function buildSortOrdering(
  field: "creation_date" | "id" | "status" | "result",
  dir: "asc" | "desc"
): string {
  const prefix = dir === "desc" ? "-" : "";
  if (field === "creation_date") return `${prefix}creation_date`;
  if (field === "id") return `${prefix}id`;
  if (field === "status") return `${prefix}status`;
  if (field === "result") return `${prefix}result`;
  return "-creation_date";
}

function normalizeListResponse(data: unknown): InvestigationListResponse {
  const payload: InvestigationListApiResponse = isObject(data) ? data : {};
  return {
    count: asNumber(payload.count, 0),
    next: typeof payload.next === "string" ? payload.next : null,
    previous: typeof payload.previous === "string" ? payload.previous : null,
    results: Array.isArray(payload.results) ? payload.results.map(normalizeRow) : [],
  };
}

function buildInvestigationListParams(params: InvestigationListParams) {
  return {
    page: (params.page ?? 0) + 1,
    page_size: params.pageSize ?? 10,
    search: params.search?.trim() || undefined,
    status: params.status && params.status !== "ALL" ? params.status : undefined,
    type: params.type && params.type !== "ALL" ? params.type : undefined,
    result: params.result && params.result !== "ALL" ? params.result : undefined,
    from_date: params.from || undefined,
    to_date: params.to || undefined,
    ordering: params.ordering ?? mapSort(params.sort),
  };
}

export async function getAllInvestigations(
  params: InvestigationListParams = {},
): Promise<InvestigationListResponse> {
  const res = await api.get("/investigations/", {
    params: buildInvestigationListParams(params),
  });
  return normalizeListResponse(res.data);
}

export async function getInvestigationDetails(
  caseId: number,
): Promise<InvestigationDetails> {
  const res = await api.get(`/investigations/${caseId}/`);
  return normalizeDetails(res.data);
}

export async function editGlobalCase(
  caseId: number,
  score: number,
  confidence: number,
  classification: string,
): Promise<InvestigationDetails> {
  const payload: EditGlobalCasePayload = { score, confidence, classification };
  const res = await api.patch(`/investigations/${caseId}/edit-global/`, payload);
  return normalizeDetails(res.data);
}

export async function redoAnalysis(
  caseId: number,
): Promise<{ status: string; dispatched: number }> {
  const res = await api.post(`/investigations/${caseId}/redo-analysis/`);
  return res.data;
}