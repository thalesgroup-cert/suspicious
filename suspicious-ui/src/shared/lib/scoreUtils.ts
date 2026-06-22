// Shared score/confidence/label helpers used by the analysis surfaces
// (submissions + investigation). Pure functions — no React, no feature types.

/** Minimal shape these helpers read off an analyzer report. */
export type ReportLike = {
  score?: number | null;
  confidence?: number | null;
  analyzer_name?: string | null;
  categories?: ReadonlyArray<string | null | undefined> | null;
  target?: { kind?: string | null; value?: string | null } | null;
};

// ---------------------------------------------------------------------------
// Score / confidence
// ---------------------------------------------------------------------------

export function clamp(n: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, n));
}

export function normalizeScore(score?: number | null) {
  if (typeof score !== "number" || Number.isNaN(score)) return 0;
  if (score <= 10) return clamp(score * 10);
  return clamp(score);
}

export function normalizeConfidence(confidence?: number | null) {
  if (typeof confidence !== "number" || Number.isNaN(confidence)) return 0;
  if (confidence <= 1) return clamp(confidence * 100);
  if (confidence <= 10) return clamp(confidence * 10);
  return clamp(confidence);
}

export function getRiskTone(score?: number | null) {
  const v = normalizeScore(score);
  if (v >= 80) {
    return {
      label: "High risk",
      color: "#ef4444",
      softBg: "rgba(239,68,68,.12)",
      softBorder: "rgba(239,68,68,.32)",
      barSx: {
        "& .MuiLinearProgress-bar": { backgroundColor: "#ef4444" },
        backgroundColor: "rgba(239,68,68,.18)",
      },
    };
  }
  if (v >= 55) {
    return {
      label: "Needs attention",
      color: "#f59e0b",
      softBg: "rgba(245,158,11,.12)",
      softBorder: "rgba(245,158,11,.32)",
      barSx: {
        "& .MuiLinearProgress-bar": { backgroundColor: "#f59e0b" },
        backgroundColor: "rgba(245,158,11,.18)",
      },
    };
  }
  return {
    label: "Low risk",
    color: "#22c55e",
    softBg: "rgba(34,197,94,.12)",
    softBorder: "rgba(34,197,94,.32)",
    barSx: {
      "& .MuiLinearProgress-bar": { backgroundColor: "#22c55e" },
      backgroundColor: "rgba(34,197,94,.18)",
    },
  };
}

export function getConfidenceTone(confidence?: number | null) {
  const v = normalizeConfidence(confidence);
  if (v >= 75) {
    return {
      label: "High confidence",
      color: "#22c55e",
      barSx: {
        "& .MuiLinearProgress-bar": { backgroundColor: "#22c55e" },
        backgroundColor: "rgba(34,197,94,.18)",
      },
    };
  }
  if (v >= 45) {
    return {
      label: "Medium confidence",
      color: "#f59e0b",
      barSx: {
        "& .MuiLinearProgress-bar": { backgroundColor: "#f59e0b" },
        backgroundColor: "rgba(245,158,11,.18)",
      },
    };
  }
  return {
    label: "Low confidence",
    color: "#94a3b8",
    barSx: {
      "& .MuiLinearProgress-bar": { backgroundColor: "#94a3b8" },
      backgroundColor: "rgba(148,163,184,.18)",
    },
  };
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

export function readStatus(status?: string) {
  const s = (status ?? "").toUpperCase();
  if (s === "DONE") return "Finished";
  if (s === "FAILED") return "Failed";
  if (s === "IN_PROGRESS") return "Running";
  if (s === "NEW") return "Queued";
  if (s === "CHALLENGED") return "Challenged";
  return status || "Unknown";
}

export function readType(type?: string) {
  const t = (type ?? "").toLowerCase();
  if (t === "file") return "File check";
  if (t === "hash") return "Hash check";
  if (t === "mail") return "Email check";
  if (t === "url") return "Link check";
  if (t === "ip") return "IP check";
  return type || "Analyzer";
}

export function summarizeForReading(report: ReportLike) {
  const risk = getRiskTone(report.score);
  const confidence = getConfidenceTone(report.confidence);
  const targetValue = report.target?.value;
  const categories = report.categories?.filter(Boolean) ?? [];
  const parts: string[] = [];
  parts.push(`${report.analyzer_name || "This analyzer"} marked this item as ${risk.label.toLowerCase()}.`);
  parts.push(`The result confidence is ${confidence.label.toLowerCase()}.`);
  if (targetValue) parts.push(`Checked item: ${targetValue}.`);
  if (categories.length) parts.push(`Detected type: ${categories.join(", ")}.`);
  return parts.join(" ");
}

export function prettySummary(summary: unknown) {
  if (!summary) return null;
  if (typeof summary === "string") return summary;
  if (Array.isArray(summary)) {
    return summary.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join("\n");
  }
  if (typeof summary === "object") {
    const obj = summary as Record<string, unknown>;
    if (typeof obj.summary === "string") return obj.summary;
    if (typeof obj.message === "string") return obj.message;
    if (typeof obj.verdict === "string") return obj.verdict;
  }
  return null;
}

export function fmtDate(iso: string) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit" });
}

export function kindLabel(kind: string) {
  const labels: Record<string, string> = {
    FILE: "File", URL: "URL", IP: "IP address", HASH: "Hash",
    DOMAIN: "Domain", MAIL: "Email address",
    MAIL_BODY: "Mail body", MAIL_HEADER: "Mail header", UNKNOWN: "Unknown",
  };
  return labels[kind.toUpperCase()] ?? kind;
}

// ---------------------------------------------------------------------------
// Group analyzer reports by artifact (target.kind + target.value).
// Generic so the caller keeps its own report type on the grouped reports.
// ---------------------------------------------------------------------------

export type ReportGroup<T = ReportLike> = {
  key: string;
  kind: string;
  value: string;
  reports: T[];
};

export function groupReportsByArtifact<T extends ReportLike>(reports: T[]): ReportGroup<T>[] {
  const order: string[] = [];
  const map: Record<string, ReportGroup<T>> = {};
  for (const report of reports) {
    const kind  = report.target?.kind  ?? "UNKNOWN";
    const value = report.target?.value ?? "—";
    const key   = `${kind}::${value}`;
    if (!map[key]) { order.push(key); map[key] = { key, kind, value, reports: [] }; }
    map[key].reports.push(report);
  }
  return order.map((k) => map[k]);
}
