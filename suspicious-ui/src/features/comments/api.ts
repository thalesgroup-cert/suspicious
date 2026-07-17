import { api } from "@/api/client";

export type CaseComment = {
  id: number;
  author_email: string;
  body: string;
  is_internal: boolean;
  created_at: string;
};

export async function getCaseComments(caseId: number): Promise<CaseComment[]> {
  const res = await api.get<CaseComment[]>(`/cases/${caseId}/comments/`);
  return res.data;
}

export async function addCaseComment(caseId: number, body: string): Promise<CaseComment> {
  const res = await api.post<CaseComment>(`/cases/${caseId}/comments/`, { body });
  return res.data;
}
