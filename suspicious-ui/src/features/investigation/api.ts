// src/features/investigation/api.ts

export type InvestigationStatus = "NEW" | "IN_PROGRESS" | "DONE" | "FAILED" | "REJECTED" | "UNKNOWN";
export type InvestigationType = "FILE" | "MAIL" | "URL" | "IP" | "HASH" | "UNKNOWN";

export type InvestigationRow = {
  id: number;
  reporter_email?: string;
  reporter_name?: string; // optional, even if you don't show it
  status: InvestigationStatus;
  info: string;
  created_at: string; // ISO
  tests_done: number;
  type: InvestigationType;
  result: string;

  // optional extras if your backend sends them
  is_challenged?: boolean;
  is_challengeable?: boolean;
};

export type InvestigationListResponse = { items: InvestigationRow[] };

/**
 * Small helper: throws on non-2xx and returns JSON.
 * Adjust base paths to match your backend.
 */
async function apiJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status} ${res.statusText}${text ? ` – ${text}` : ""}`);
  }

  return (await res.json()) as T;
}

/**
 * List all investigations (analyst view).
 * Change the URL to your real endpoint.
 */
export async function getAllInvestigations(): Promise<InvestigationListResponse> {
  // Example: "/api/investigation"
  return apiJson<InvestigationListResponse>("/api/investigation");
}

/**
 * Get a single case details.
 * Change the URL to your real endpoint.
 */
export async function getInvestigationDetails(caseId: number): Promise<any> {
  // Example: `/api/investigation/${caseId}`
  return apiJson<any>(`/api/investigation/${caseId}`);
}

/**
 * Global override edit (score/confidence/classification).
 * This mirrors your old `../edit-global/${caseId}/${score}/${confidence}/${classification}` behavior,
 * but as a JSON POST by default.
 *
 * If your backend is still path-params GET, set USE_LEGACY_EDIT_GLOBAL=true and adjust URLs below.
 */
export async function editGlobalCase(
  caseId: number,
  score: number,
  confidence: number,
  classification: string
): Promise<any> {
  const useLegacy = import.meta.env.VITE_USE_LEGACY_EDIT_GLOBAL === "true";

  if (useLegacy) {
    // Legacy style: ../edit-global/:caseId/:score/:confidence/:classification
    return apiJson<any>(`../edit-global/${caseId}/${score}/${confidence}/${encodeURIComponent(classification)}`);
  }

  // Modern style: POST JSON
  return apiJson<any>(`/api/investigation/${caseId}/edit-global`, {
    method: "POST",
    body: JSON.stringify({ score, confidence, classification }),
  });
}
