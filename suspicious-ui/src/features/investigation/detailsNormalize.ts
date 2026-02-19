// src/features/submissions/detailsNormalize.ts
export type AnalyzerHit = {
  analyzer_name: string;
  score: number; // 0..10
  confidence: number; // 0..100
  level?: string | null;
  status?: string | null;

  // optional fields your backend might send
  data?: string | null;
  artifact?: string | null;

  // optional hints
  type?: string | null; // e.g. "file", "hash", "url", "ip", "mail-body", "mail-header", "attachment", ...
  source?: string | null;
};

export type AnalyzerGroup = {
  /** stable key for rendering */
  key: string;
  /** section label shown to user */
  title: string;
  /** optional subtitle (e.g. file name / artifact) */
  subtitle?: string;
  /** normalized type bucket */
  kind:
    | "file"
    | "hash"
    | "url"
    | "ip"
    | "mail_header"
    | "mail_body"
    | "attachment"
    | "artifact"
    | "unknown";
  /** artifact identifier (hash/url/ip/etc) if available */
  artifact?: string;
  /** analyzers for this group */
  analyzers: AnalyzerHit[];
};

function toNum(x: unknown, fallback = 0) {
  const n = typeof x === "number" ? x : typeof x === "string" ? Number(x) : NaN;
  return Number.isFinite(n) ? n : fallback;
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

function asStr(x: unknown): string | null {
  if (x == null) return null;
  const s = String(x).trim();
  return s.length ? s : null;
}

/**
 * Accepts:
 * - array of analyzer hits
 * - stringified JSON
 * - nested shapes where analyzers may live under common keys
 *
 * Normalize to AnalyzerHit[].
 */
export function normalizeAnalyzers(input: unknown): AnalyzerHit[] {
  const raw = extractAnalyzers(input);
  if (!Array.isArray(raw)) return [];

  return raw
    .map((x: any) => {
      const analyzer_name = asStr(x?.analyzer_name ?? x?.name ?? x?.analyzer) ?? "UNKNOWN";
      const score = clamp(toNum(x?.score, 0), 0, 10);
      const confidence = clamp(toNum(x?.confidence, 0), 0, 100);

      return {
        analyzer_name,
        score,
        confidence,
        level: asStr(x?.level),
        status: asStr(x?.status),
        data: asStr(x?.data),
        artifact: asStr(x?.artifact ?? x?.ioc ?? x?.value),
        type: asStr(x?.type ?? x?.artifact_type ?? x?.kind),
        source: asStr(x?.source),
      } satisfies AnalyzerHit;
    })
    .filter((x) => x.analyzer_name && x.analyzer_name !== "null");
}

/**
 * Groups analyzers like the old page:
 * - by "kind" (file/hash/url/ip/mail header/mail body/attachment/artifact)
 * - then by artifact value
 *
 * If your backend provides "type" or good "artifact" fields, grouping will be strong.
 * If not, it will fall back to a single "Unknown" group.
 */
export function groupAnalyzers(hits: AnalyzerHit[], detailsPayload?: unknown): AnalyzerGroup[] {
  if (!hits.length) return [];

  // optional: extract some nicer labels from details payload (file name, url, etc.)
  const ctx = extractContext(detailsPayload);

  const bucketed = new Map<string, AnalyzerGroup>();

  for (const h of hits) {
    const kind = inferKind(h, ctx);
    const artifact = inferArtifact(h, ctx);

    const title = kindTitle(kind);
    const subtitle = subtitleFor(kind, artifact, ctx);

    const key = `${kind}::${artifact ?? "no-artifact"}`;

    const existing = bucketed.get(key);
    if (existing) {
      existing.analyzers.push(h);
    } else {
      bucketed.set(key, {
        key,
        title,
        subtitle,
        kind,
        artifact: artifact ?? undefined,
        analyzers: [h],
      });
    }
  }

  const groups = Array.from(bucketed.values());

  // stable sorting: by kind priority, then highest score in group
  groups.sort((a, b) => {
    const pa = kindPriority(a.kind);
    const pb = kindPriority(b.kind);
    if (pa !== pb) return pa - pb;

    const sa = maxScore(a.analyzers);
    const sb = maxScore(b.analyzers);
    if (sb !== sa) return sb - sa;

    return (a.artifact ?? "").localeCompare(b.artifact ?? "");
  });

  // inside each group: best first
  for (const g of groups) {
    g.analyzers.sort((a, b) => (b.score - a.score) || (b.confidence - a.confidence) || a.analyzer_name.localeCompare(b.analyzer_name));
  }

  return groups;
}

function maxScore(list: AnalyzerHit[]) {
  let m = 0;
  for (const x of list) m = Math.max(m, x.score);
  return m;
}

/** try to infer a group kind from hit.type or artifact patterns */
function inferKind(h: AnalyzerHit, ctx: ReturnType<typeof extractContext>): AnalyzerGroup["kind"] {
  const t = (h.type ?? "").toLowerCase();

  if (t.includes("mail-header") || t.includes("header")) return "mail_header";
  if (t.includes("mail-body") || t.includes("body")) return "mail_body";
  if (t.includes("attachment")) return "attachment";
  if (t === "file") return "file";
  if (t === "hash") return "hash";
  if (t === "url") return "url";
  if (t === "ip" || t.includes("ip")) return "ip";
  if (t.includes("artifact")) return "artifact";

  // infer by artifact value patterns
  const a = (h.artifact ?? "").trim();
  if (looksLikeUrl(a)) return "url";
  if (looksLikeIp(a)) return "ip";
  if (looksLikeHash(a)) return "hash";

  // if details has a single known main type, prefer it
  if (ctx.mainType) {
    const mt = ctx.mainType.toLowerCase();
    if (mt.includes("file")) return "file";
    if (mt.includes("mail")) return "mail_body";
    if (mt.includes("url")) return "url";
    if (mt.includes("ip")) return "ip";
    if (mt.includes("hash")) return "hash";
  }

  return "unknown";
}

function inferArtifact(h: AnalyzerHit, ctx: ReturnType<typeof extractContext>): string | null {
  if (h.artifact) return h.artifact;
  if (h.data) return h.data;

  // fallback to main artifacts from details context
  if (ctx.mainArtifact) return ctx.mainArtifact;
  return null;
}

function kindTitle(kind: AnalyzerGroup["kind"]) {
  switch (kind) {
    case "file":
      return "File";
    case "hash":
      return "Hash";
    case "url":
      return "URL";
    case "ip":
      return "IP";
    case "mail_header":
      return "Mail header";
    case "mail_body":
      return "Mail body";
    case "attachment":
      return "Attachment";
    case "artifact":
      return "Artifact";
    default:
      return "Unknown";
  }
}

function subtitleFor(kind: AnalyzerGroup["kind"], artifact: string | null, ctx: ReturnType<typeof extractContext>) {
  // try to show human-friendly subtitle first (file name, etc.)
  if (kind === "file" && ctx.fileName) return ctx.fileName;
  if (artifact) return artifact;
  if (kind === "file" && ctx.fileHash) return ctx.fileHash;
  if (kind === "url" && ctx.url) return ctx.url;
  if (kind === "ip" && ctx.ip) return ctx.ip;
  if (kind === "hash" && ctx.hash) return ctx.hash;
  return undefined;
}

function kindPriority(kind: AnalyzerGroup["kind"]) {
  switch (kind) {
    case "file":
      return 1;
    case "attachment":
      return 2;
    case "hash":
      return 3;
    case "url":
      return 4;
    case "ip":
      return 5;
    case "mail_header":
      return 6;
    case "mail_body":
      return 7;
    case "artifact":
      return 8;
    default:
      return 99;
  }
}

/** Extracts some “old page” fields if present in details payload */
function extractContext(detailsPayload: unknown) {
  const o = (detailsPayload && typeof detailsPayload === "object") ? (detailsPayload as any) : null;

  const fileName = asStr(o?.file_name ?? o?.file?.name ?? o?.file?.file_name);
  const fileHash = asStr(o?.file_hash ?? o?.file?.hash ?? o?.file?.file_hash);
  const url = asStr(o?.url ?? o?.url_value);
  const ip = asStr(o?.ip ?? o?.ip_value);
  const hash = asStr(o?.hash ?? o?.hash_value);
  const mainType = asStr(o?.type ?? o?.submission_type ?? o?.context?.type ?? o?.context?.submission_type);

  const mainArtifact =
    asStr(o?.artifact) ??
    fileHash ??
    fileName ??
    url ??
    ip ??
    hash ??
    asStr(o?.value);

  return { fileName, fileHash, url, ip, hash, mainType, mainArtifact };
}

function extractAnalyzers(input: unknown): unknown {
  if (!input) return [];

  if (Array.isArray(input)) return input;

  if (typeof input === "string") {
    try {
      const parsed = JSON.parse(input);
      return extractAnalyzers(parsed);
    } catch {
      return [];
    }
  }

  if (typeof input === "object") {
    const o: any = input;

    const candidates = [
      o.analyzers,
      o.case_analyzers,
      o.file_analyzers,
      o.url_analyzers,
      o.hash_analyzers,
      o.ip_analyzers,
      o.mail_analyzers,
      o.attachments_analyzers,
      o.artifacts_analyzers,
      o.results?.analyzers,
      o.context?.analyzers,
      o.details?.analyzers,
    ];

    for (const c of candidates) {
      const found = extractAnalyzers(c);
      if (Array.isArray(found) && found.length) return found;
    }

    // fallback: shallow scan values
    for (const v of Object.values(o)) {
      const found = extractAnalyzers(v);
      if (Array.isArray(found) && found.length) return found;
    }
  }

  return [];
}

function looksLikeIp(s: string) {
  // basic IPv4 check
  const m = s.match(/^(\d{1,3}\.){3}\d{1,3}$/);
  if (!m) return false;
  return s.split(".").every((p) => {
    const n = Number(p);
    return Number.isFinite(n) && n >= 0 && n <= 255;
  });
}

function looksLikeUrl(s: string) {
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function looksLikeHash(s: string) {
  // md5/sha1/sha256-ish
  const t = s.replace(/\s+/g, "");
  return /^[a-fA-F0-9]{32}$/.test(t) || /^[a-fA-F0-9]{40}$/.test(t) || /^[a-fA-F0-9]{64}$/.test(t);
}
