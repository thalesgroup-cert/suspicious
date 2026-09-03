export type SubmitConfigResponse = {
  status: "success";
  data: {
    suspicious_email: string;
  };
};

export type SubmitSuccessResponse = {
  status: "success";
  accepted: boolean;
  submission_type: "url" | "other" | "file";
  result_type: "case" | "mail";
  case_id: number | string | null;
  id?: number | string | null;
  message: string;
};

export type ApiErrorResponse = {
  status?: "error";
  code?: string;
  detail?: string;
  non_field_errors?: string[];
} & Record<string, unknown>;

export type SubmitIndicatorsResponse = {
  status: "success";
  case_id: number;
  observable_count: number;
  accepted: boolean;
  skipped: string[];
};

export type SubmitMode = "file" | "artifact" | "indicators";

export type ArtifactKind = "url" | "ioc";
