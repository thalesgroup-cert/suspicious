import { api } from "@/api/client";
import type {
  SubmitConfigResponse,
  SubmitIndicatorsResponse,
  SubmitSuccessResponse,
} from "@/features/submit/types";

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

export async function submitIndicators(input: {
  indicators: string;
  context?: string;
}): Promise<SubmitIndicatorsResponse> {
  const res = await api.post("/submit/indicators/", input);
  return res.data;
}

export type ExtractIocsResponse = {
  status: "success";
  indicators: string;
  found: number;
  skipped: string[];
};

/** Extract candidate IOCs from an uploaded .txt/.csv/.json list — no case created. */
export async function extractIocsFromFile(file: File): Promise<ExtractIocsResponse> {
  const form = new FormData();
  form.append("file", file);
  const res = await api.post("/submit/indicators/extract/", form);
  return res.data;
}

export async function getSubmitConfig(): Promise<string> {
  const res = await api.get<SubmitConfigResponse>("/submit/config/");
  return res.data.data.suspicious_email;
}
