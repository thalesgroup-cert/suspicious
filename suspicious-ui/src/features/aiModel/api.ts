import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";

const base = endpoints.aiModel;

export type Paged<T> = { count: number; next: string | null; previous: string | null; results: T[] };
/** limit/offset, or the per-prefix keys of the shadow and queue sub-lists (e.g. flips_limit). */
export type PageParams = Record<string, number | string | undefined>;

export type VersionStatus = "candidate" | "shadow" | "active" | "previous" | "discarded" | "failed";

export type VersionSummary = {
  version_id: string;
  status: VersionStatus;
  trigger: string;
  created_at: string;
  shadow_since: string | null;
  shadow_min_days: number;
  recheck: { passed: boolean | null; finished_at: string | null } | null;
};

export type JobRow = {
  job_id: string;
  /** "recheck": a gate recheck of the shadow, which never makes a candidate. */
  kind: "retrain" | "recheck";
  state: string;
  trigger: string;
  rows: number | null;
  excluded_rows: number | null;
  started_at: string;
  finished_at: string | null;
  error: string;
};

export type LedgerSummary = {
  by_source: Record<string, Record<string, number>>;
  flagged: number;
  trainable: number;
};

export type AiModelStatus = {
  active: VersionSummary | null;
  previous: VersionSummary | null;
  shadow: VersionSummary | null;
  job_running: boolean;
  job_id: string | null;
  health: { ok: boolean | null; detail: string; checked_at: string | null };
  breaker: { state: "closed" | "open" | "half-open" | "unknown"; since: string | null };
  schedule: { enabled: boolean; interval_days: number; next_run: string | null; backoff_until: string | null };
  counts: Record<VersionStatus, number>;
  jobs: JobRow[];
  ledger: LedgerSummary;
};

export type VersionRow = VersionSummary & {
  stats: { scored: number; dangerous: number; checks: number; created: number; joined: number; alerts: number };
  purity: { labelled: number; dangerous: number; purity: number | null; warning: boolean };
  age_warning: boolean;
};

/** Gate payload, whitelisted server side (Ruling G5); every part may be absent or null. */
export type GateCheck = { passed?: boolean; value?: number | string | null; threshold?: number | string | null; detail?: string };
export type Gate = {
  checks: Record<string, GateCheck> | null;
  candidate: Record<string, number | string | null> | null;
  baseline: Record<string, number | string | null> | null;
  campaign: {
    dangerous_called_safe?: number | null;
    baseline_dangerous_called_safe?: number | null;
    groups?: number | null;
    fallback?: boolean;
  } | null;
  tier_cutoffs: { high?: number | null; medium?: number | null } | null;
};

export type CandidateRow = {
  version_id: string;
  status: VersionStatus;
  created_at: string;
  trigger: string;
  rows: number | null;
  excluded_rows: number | null;
  eligible: boolean;
  gate: Gate | null;
};

export type Agreement = { agree: number; total: number };
export type SubList<T> = { count: number; results: T[] };

export type ShadowDetail = VersionSummary & {
  live_results: number;
  agreement: { class: Agreement; verdict: Agreement };
  flips: SubList<{ case_id: number; flip: string; live_result: string; would_be_result: string; reviewable: boolean; reviewed?: boolean }>;
  campaign_effects: SubList<{ case_id: number; effect: string; live_campaign_id: string | null; reviewable: boolean; reviewed?: boolean }>;
  alert_delta: { candidate_only: SubList<number>; active_only: SubList<number> };
  conditions: string[];
};
export type ShadowResponse = { shadow: null } | ShadowDetail;

export type ReviewKind = "flip" | "campaign";
export type ReviewRow = { version_id: string; kind: ReviewKind; case_id: number; user: string | null; note: string; at: string };

export type LabelMix = {
  now: Record<string, number>;
  before: Record<string, number>;
  rows: { now: number; before: number };
  jump: { class: string; from: number; to: number } | null;
};
export type LedgerResponse = LedgerSummary & { mix: LabelMix };

export type FlagRow = {
  id: number;
  case_id: number | null;
  label_class: string;
  source: string;
  flag_reason: string;
  observed_at: string;
};

export type Disagreement = { case_id: number; verdict: string; ai_class: string; date: string };
export type CampaignConflict = { campaign_ref: string; classes: string[]; date: string };
export type QueueResponse = {
  disagreements: SubList<Disagreement>;
  campaign_conflicts: SubList<CampaignConflict>;
};

const get = async <T>(path: string, params?: PageParams): Promise<T> => (await api.get(`${base}${path}`, { params })).data;
const post = async <T>(path: string, body: object = {}): Promise<T> => (await api.post(`${base}${path}`, body)).data;

export type Note = { note?: string };
/** version_id: the version the screen shows, so a stale screen is refused (409 state_changed). */
export type VersionAction = Note & { version_id?: string };

export const getStatus = () => get<AiModelStatus>("status/");
export const getVersions = (p?: PageParams) => get<Paged<VersionRow>>("versions/", p);
export const getCandidates = (p?: PageParams) => get<Paged<CandidateRow>>("candidates/", p);
export const getShadow = (p?: PageParams) => get<ShadowResponse>("shadow/", p);
export const getReviews = (p?: PageParams) => get<Paged<ReviewRow>>("reviews/", p);
export const getJobs = (p?: PageParams) => get<Paged<JobRow>>("jobs/", p);
export const getLedger = () => get<LedgerResponse>("ledger/");
export const getFlags = (p?: PageParams) => get<Paged<FlagRow>>("flags/", p);
export const getQueue = (p?: PageParams) => get<QueueResponse>("queue/", p);

export const postShadowStart = (b: VersionAction & { version_id: string }) => post<VersionSummary>("shadow/start/", b);
export const postPromote = (b: VersionAction) => post<VersionSummary>("promote/", b);
export const postRollback = (b: VersionAction) => post<VersionSummary>("rollback/", b);
export const postDiscard = (b: VersionAction & { expected_status?: VersionStatus }) => post<VersionSummary>("discard/", b);
export const postExtend = (b: VersionAction & { days: number }) => post<VersionSummary>("extend/", b);
export const postRecheck = (b: VersionAction) => post<{ job_id: string }>("recheck/", b);
export const postReview = (b: VersionAction & { kind: ReviewKind; case_id: number; note: string }) =>
  post<{ version_id: string; kind: ReviewKind; case_id: number }>("reviews/", b);
export const postRetrain = (b: Note = {}) => post<{ job_id: string }>("retrain/", b);
export const postResolveFlag = ({ id, keep, note }: { id: number; keep: boolean; note: string }) =>
  post<FlagRow>(`flags/${id}/resolve/`, { keep, note });
export const postResetBreaker = () => post<{ epoch: number }>("breaker/reset/");
