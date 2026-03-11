import { api } from "@/api/client";

export type SubmissionStatus =
  | "NEW"
  | "IN_PROGRESS"
  | "DONE"
  | "CHALLENGED"
  | "FAILED"
  | "REJECTED"
  | "UNKNOWN";

export type SubmissionType =
  | "FILE"
  | "MAIL"
  | "URL"
  | "IP"
  | "HASH"
  | "UNKNOWN";

export type SubmissionRow = {
  id: number;
  status: SubmissionStatus;
  artifact: string;
  created_at: string;
  tests_done: number;
  type: SubmissionType;
  result: string;
  is_challengeable: boolean;
  is_challenged: boolean;
};

export type SubmissionAnalyzerReport = {
  id: number;
  cortex_job_id: string;
  type: string;
  status: string;
  analyzer_name: string;
  analyzer_id: string;
  level: string;
  confidence: number;
  score: number;
  category: string | null;
  categories: string[];
  report_summary: any;
  report_taxonomy: any;
  report_full: any;
  target: {
    kind: string;
    id: number | null;
    value: string | null;
  };
  created_at: string;
};

export type SubmissionDetails = SubmissionRow & {
  analyzer_reports: SubmissionAnalyzerReport[];
  raw: any;
};

export async function getMySubmissions(): Promise<{ items: SubmissionRow[] }> {
  const res = await api.get("/submissions/mine/");
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