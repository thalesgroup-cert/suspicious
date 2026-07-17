import axios from "axios";
import type {
  ApiErrorResponse,
  ArtifactKind,
  SubmitSuccessResponse,
} from "@/features/submit/types";

export function extractApiErrorMessage(error: unknown): string {
  if (!axios.isAxiosError(error)) {
    return "Request failed.";
  }

  const data = error.response?.data as ApiErrorResponse | undefined;
  if (!data) {
    return error.message || "Request failed.";
  }

  if (typeof data.detail === "string" && data.detail.trim()) {
    return data.detail;
  }

  const fieldMessages = Object.entries(data)
    .filter(([key]) => key !== "status" && key !== "code" && key !== "detail")
    .flatMap(([key, value]) => {
      if (Array.isArray(value)) {
        return value.map((msg) => `${key}: ${String(msg)}`);
      }
      if (typeof value === "string") {
        return [`${key}: ${value}`];
      }
      return [];
    });

  if (fieldMessages.length > 0) {
    return fieldMessages.join(" ");
  }

  return error.message || "Request failed.";
}

export function resolveId(res: SubmitSuccessResponse): string | number | null {
  return res.case_id ?? res.id ?? null;
}

export function formatBytes(bytes: number) {
  const units = ["B", "KB", "MB", "GB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

export const FULL_URL_RE = /^https?:\/\/.+/i;

/**
 * Matches bare hostnames / domains with an optional path.
 * Does NOT match plain IPs (handled as IOC) or hashes (no dots).
 *
 * Matches:   evil.com  sub.evil.co.uk  evil.com/path?q=1
 * No match:  192.168.1.1  abc123deadbeef  malware
 */
export const BARE_DOMAIN_RE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(\/.*)?$/i;

export function classifyArtifact(raw: string): ArtifactKind {
  const v = raw.trim();
  if (FULL_URL_RE.test(v)) return "url";
  if (BARE_DOMAIN_RE.test(v)) return "url";
  return "ioc";
}

/**
 * Ensures the value sent to /submit/url/ always carries a scheme.
 * Django URLField rejects scheme-less strings, so bare domains get http://.
 */
export function normaliseUrl(raw: string): string {
  const v = raw.trim();
  return FULL_URL_RE.test(v) ? v : `http://${v}`;
}
