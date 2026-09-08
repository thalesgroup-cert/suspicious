import { api } from "@/api/client";

export type DangerCounts = {
  safe?: number;
  inconclusive?: number;
  suspicious?: number;
  dangerous?: number;
};

export type HomeSummary = {
  show_scope_modal: boolean;
  monthly: {
    everyone_items?: number;
    scope_items?: number;
    scope_name?: string | null;
  };
  danger_counts?: DangerCounts;
  scope_danger_counts?: DangerCounts | null;
  suggested_scopes?: {
    region?: string | null;
    country?: string | null;
    gbu?: string | null;
  };
  spotlight?: {
    title: string;
    description: string;
    cta_label: string;
    cta_path: string;
  };
};

export async function getHomeSummary(params?: {
  month?: number;
  year?: number;
}): Promise<HomeSummary> {
  const res = await api.get("/home/summary/", { params });
  return res.data;
}

/** Set the caller's CISO management scope. "ALL" or a pipe-joined subset of
 *  their own region/country/gbu (validated server-side). */
export async function setCisoScope(input: { scope: string }): Promise<{ scope: string }> {
  const res = await api.patch("/profile/", input);
  return res.data;
}
