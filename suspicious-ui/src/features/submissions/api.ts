import { api } from "@/api/client";

export type SubmissionStatus =
  | "NEW"
  | "IN_PROGRESS"
  | "DONE"
  | "CHALLENGED"
  | "UNKNOWN";

export type SubmissionType =
  | "FILE"
  | "MAIL"
  | "URL"
  | "IP"
  | "HASH"
  | "UNKNOWN";

export type SubmissionResult =
  | "SAFE"
  | "INCONCLUSIVE"
  | "UNCHALLENGED"
  | "ALLOW_LISTED"
  | "FAILURE"
  | "SUSPICIOUS"
  | "DANGEROUS"
  | "UNKNOWN";

type AnalyzerTargetKind =
  | "URL"
  | "DOMAIN"
  | "MAIL"
  | "HASH"
  | "FILE"
  | "IP"
  | "MAIL_BODY"
  | "MAIL_HEADER"
  | "UNKNOWN";

export type SubmissionRow = {
  id: number;
  status: SubmissionStatus;
  artifact: string;
  created_at: string;
  tests_done: number;
  type: SubmissionType;
  result: SubmissionResult;
  is_challengeable?: boolean;
  is_challenged?: boolean;
  /** Relative URL to the rendered .eml→png preview, or null when absent / not a mail. */
  mail_preview_url?: string | null;
};

export type SubmissionAnalyzerReport = {
  id: number;
  cortex_job_id: string | null;
  type: string;
  status: string;
  analyzer_name: string;
  analyzer_id: string;
  level: string | null;
  confidence: number | null;
  score: number | null;
  category: string | null;
  categories: string[];
  report_summary: unknown;
  report_taxonomy: unknown;
  report_full: unknown;
  target: {
    kind: AnalyzerTargetKind;
    id: number | null;
    value: string | null;
  };
  created_at: string;
};

type SubmissionRawDetails = {
  case: Record<string, unknown>;
  fileOrMail: {
    id: number;
    file_id: number | null;
    mail_id: number | null;
  } | null;
  nonFileIocs: {
    id: number;
    url_id: number | null;
    ip_id: number | null;
    hash_id: number | null;
  } | null;
  analyzer_report_ids: number[];
};

export type SubmissionCaseInfos = {
  score: number | null;
  confidence: number | null;
  classification: string;
  score_ai: number | null;
  confidence_ai: number | null;
  classification_ai: string;
  category_ai: string | null;
};

export type UrlArtifact = {
  id: number;
  address: string;
  analysis_status: "pending" | "analyzed" | "reused" | "skipped";
  interestingness: number;
  canonical_key: string;
  analyzed_url_id: number | null;
};

export type SubmissionDetails = SubmissionRow & {
  analyzer_reports: SubmissionAnalyzerReport[];
  case_infos?: SubmissionCaseInfos;
  raw?: SubmissionRawDetails;
  url_artifacts?: UrlArtifact[];
};

export type SubmissionOrdering =
  | "created_at"
  | "-created_at"
  | "id"
  | "-id"
  | "status"
  | "-status"
  | "result"
  | "-result";

export type PaginatedSubmissionsResponse = {
  count: number;
  next: string | null;
  previous: string | null;
  results: SubmissionRow[];
};

export type ListSubmissionsParams = {
  mine?: boolean;
  ordering?: SubmissionOrdering;
  page?: number;
  page_size?: number;
  search?: string;
};

export async function listSubmissions(
  params: ListSubmissionsParams = {}
): Promise<PaginatedSubmissionsResponse> {
  const res = await api.get("/submissions/", { params });
  return res.data;
}

export async function getSubmissionDetails(id: number): Promise<SubmissionDetails> {
  const res = await api.get(`/submissions/${id}/`);
  return res.data;
}

export async function challengeSubmission(id: number): Promise<{ detail: string }> {
  const res = await api.post(`/submissions/${id}/challenge/`);
  return res.data;
}

export type AnalyzeUrlResponse = { status: string; url_id: number };

export async function analyzeUrl(
  submissionId: number,
  urlId: number,
): Promise<AnalyzeUrlResponse> {
  const res = await api.post<AnalyzeUrlResponse>(
    `/submissions/${submissionId}/urls/${urlId}/analyze/`,
  );
  return res.data;
}