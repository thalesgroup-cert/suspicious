import { api } from "@/api/client";

export type SubmissionType = "FILE" | "MAIL" | "URL" | "IP" | "HASH" | "UNKNOWN";

export type SubmissionStatus =
  | "NEW"
  | "IN_PROGRESS"
  | "DONE"
  | "FAILED"
  | "REJECTED"
  | "UNKNOWN";

export type SubmissionRow = {
  id: number;
  status: SubmissionStatus;
  info: string;          // filename / subject / ioc
  created_at: string;    // ISO string
  tests_done: number;    // analysis_done
  type: SubmissionType;
  result: string;        // results
  is_challengeable: boolean;
  is_challenged: boolean;
};

export type SubmissionsResponse = {
  items: SubmissionRow[];
};

export async function getMySubmissions(): Promise<SubmissionsResponse> {
  // adapte l’URL à ton backend
  const res = await api.get("/submissions/");
  return res.data;
}

export async function getSubmissionDetails(id: number): Promise<any> {
  // adapte l’URL à ton backend
  const res = await api.get(`/submissions/${id}/`);
  return res.data;
}

export async function challengeSubmission(id: number): Promise<{ ok: boolean }> {
  // adapte l’URL à ton backend
  const res = await api.post(`/submissions/${id}/challenge/`);
  return res.data;
}
