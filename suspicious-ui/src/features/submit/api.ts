import { api } from "@/api/client";
import type { SubmitConfigResponse, SubmitSuccessResponse } from "@/features/submit/types";

export async function submitUrl(input: {
  url: string;
  context?: string;
}): Promise<SubmitSuccessResponse> {
  const res = await api.post("/submit/url/", input);
  return res.data;
}

export async function submitIoc(input: {
  value: string;
  context?: string;
}): Promise<SubmitSuccessResponse> {
  const res = await api.post("/submit/other/", input);
  return res.data;
}

export async function submitFile(input: {
  file: File;
  context?: string;
}): Promise<SubmitSuccessResponse> {
  const form = new FormData();
  form.append("file", input.file);
  if (input.context) form.append("context", input.context);
  const res = await api.post("/submit/file/", form);
  return res.data;
}

export async function getSubmitConfig(): Promise<string> {
  const res = await api.get<SubmitConfigResponse>("/submit/config/");
  return res.data.data.suspicious_email;
}
