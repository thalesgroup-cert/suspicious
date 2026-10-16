/**
 * Fictional "Meridian Group" data for the product demo video.
 *
 * Everything here is invented: reserved domains (.example, .test), TEST-NET
 * addresses (203.0.113.0/24, 198.51.100.0/24) and made-up people. Nothing
 * touches a real backend — `installMocks` answers every `/api/**` call.
 */
import type { Page, Route } from "@playwright/test";

// ─── Identity ───────────────────────────────────────────────────────────────

const USER = {
  id: 1,
  username: "elena.voss@meridian.example",
  email: "elena.voss@meridian.example",
  first_name: "Elena",
  last_name: "Voss",
  groups: ["CERT", "Admin"],
  ciso_scope: "ALL",
  theme: "light",
  auto_seasonal: false,
};

const PROFILE = {
  ...USER,
  function: "CERT analyst",
  region: "EMEA",
  country: "FR",
  gbu: "Security",
  scope: "ALL",
  wants_acknowledgement: true,
  wants_results: true,
  theme: "light",
  auto_seasonal: false,
  sidebar_pinned: false,
  photo_url: null,
  creation_date: "2025-03-04T09:00:00Z",
  last_update: "2026-10-01T08:30:00Z",
  tour_completed: true, // otherwise the onboarding tour overlays the recording
};

// ─── Cases ──────────────────────────────────────────────────────────────────

const iso = (daysAgo: number, hour = 9, minute = 12) => {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - daysAgo);
  d.setUTCHours(hour, minute, 0, 0);
  return d.toISOString();
};

type Row = {
  id: number;
  reporter_email: string;
  status: string;
  info: string;
  artifact: string;
  created_at: string;
  tests_done: number;
  type: string;
  result: string;
  is_challengeable: boolean;
  is_challenged: boolean;
  mail_preview_url: string | null;
};

const row = (r: Partial<Row> & Pick<Row, "id" | "type" | "artifact" | "result">): Row => ({
  reporter_email: "jordan.kim@meridian.example",
  status: "DONE",
  info: r.artifact,
  created_at: iso(1),
  tests_done: 6,
  is_challengeable: false,
  is_challenged: false,
  mail_preview_url: null,
  ...r,
});

const ROWS: Row[] = [
  row({
    id: 42,
    type: "MAIL",
    artifact: "Action required: payroll update for October",
    result: "DANGEROUS",
    reporter_email: "camila.reyes@meridian.example",
    created_at: iso(0, 8, 41),
    tests_done: 7,
  }),
  row({
    id: 41,
    type: "URL",
    artifact: "https://meridian-sso-verify.example/login",
    result: "SUSPICIOUS",
    reporter_email: "haruto.sato@meridian.example",
    created_at: iso(0, 7, 5),
    tests_done: 5,
    is_challengeable: true,
  }),
  row({
    id: 40,
    type: "FILE",
    artifact: "Invoice_Q3_meridian.xlsm",
    result: "DANGEROUS",
    reporter_email: "sam.whitfield@meridian.example",
    created_at: iso(1, 16, 20),
    tests_done: 8,
  }),
  row({
    id: 39,
    type: "MAIL",
    artifact: "Team lunch this Friday?",
    result: "SAFE",
    created_at: iso(1, 11, 3),
    tests_done: 4,
  }),
  row({
    id: 38,
    type: "IP",
    artifact: "203.0.113.77",
    result: "INCONCLUSIVE",
    reporter_email: "sam.whitfield@meridian.example",
    created_at: iso(2, 14, 48),
    tests_done: 3,
  }),
  row({
    id: 37,
    type: "MAIL",
    artifact: "Your parcel could not be delivered",
    result: "SUSPICIOUS",
    reporter_email: "adaeze.okafor@meridian.example",
    created_at: iso(3, 9, 30),
    tests_done: 6,
  }),
  row({
    id: 36,
    type: "HASH",
    artifact: "9f2b4c7a51e0d3c8a6b7f1e2d4c5a8b9",
    result: "SAFE",
    created_at: iso(4, 10, 15),
    tests_done: 2,
  }),
];

// The case created live during the demo (bulk indicators → one IOC case).
const NEW_CASE_ID = 43;
const NEW_ROW = row({
  id: NEW_CASE_ID,
  type: "IOC",
  artifact: "3 indicators",
  info: "3 indicator(s)",
  result: "DANGEROUS",
  reporter_email: USER.email,
  created_at: new Date().toISOString(),
  tests_done: 6,
});

// ─── Case detail ────────────────────────────────────────────────────────────

const report = (
  id: number,
  analyzer_name: string,
  level: string,
  score: number,
  confidence: number,
  category: string,
  target: { kind: string; value: string },
) => ({
  id,
  cortex_job_id: `cj-${1000 + id}`,
  type: target.kind.toLowerCase(),
  status: "SUCCESS",
  analyzer_name,
  analyzer_id: `${analyzer_name}_1_0`,
  level,
  confidence,
  score,
  category,
  categories: [category],
  report_summary: {},
  report_taxonomy: {},
  report_full: {},
  enrichment: null,
  target: { kind: target.kind, id: id, value: target.value },
  created_at: iso(0, 8, 44),
});

const MAIL_REPORTS = [
  report(1, "AIMailAnalyzer", "malicious", 9.7, 94, "Phishing", {
    kind: "MAIL",
    value: ROWS[0].artifact,
  }),
  report(2, "YaraRules", "suspicious", 6.2, 80, "Credential lure", {
    kind: "MAIL_BODY",
    value: "body.html",
  }),
  report(3, "MailHeaderInspector", "suspicious", 7.0, 85, "Spoofed sender", {
    kind: "MAIL_HEADER",
    value: "Return-Path mismatch",
  }),
  report(4, "UrlReputation", "malicious", 9.3, 90, "Phishing", {
    kind: "URL",
    value: "https://meridian-payroll-update.example/sso",
  }),
  report(5, "Sandbox", "safe", 1.0, 60, "No behaviour", {
    kind: "URL",
    value: "https://meridian-payroll-update.example/sso",
  }),
];

const VERDICT_MAIL = {
  band: "Dangerous",
  confidence: 94,
  decisive_rule: "Two independent tier-1 sources agree on malicious.",
  analyst_paragraph:
    "The ML classifier and URL reputation both flag this message as credential phishing. " +
    "The Return-Path domain does not match the visible sender, and the link points to a " +
    "look-alike domain registered 2 days ago.",
  reporter_paragraph:
    "This email is a phishing attempt. Do not click the link. Thank you for reporting it.",
  confidence_reading: "High confidence: independent sources agree.",
  sources: [
    { name: "AIMailAnalyzer", tier: 1, verdict: "malicious", counted: true, note: "Phishing 97%" },
    { name: "UrlReputation", tier: 1, verdict: "malicious", counted: true, note: "Newly registered look-alike domain" },
    { name: "MailHeaderInspector", tier: 2, verdict: "suspicious", counted: true, note: "Return-Path mismatch" },
    { name: "YaraRules", tier: 2, verdict: "suspicious", counted: true, note: "Credential-lure strings" },
    { name: "Sandbox", tier: 3, verdict: "clean", counted: false, note: "Landing page blocked bots" },
  ],
};

const IOC_URL = "https://meridian-payroll-update.example/sso";
const IOC_REPORTS = [
  report(11, "UrlReputation", "malicious", 9.3, 90, "Phishing", { kind: "URL", value: IOC_URL }),
  report(12, "Sandbox", "suspicious", 6.4, 78, "Credential form", { kind: "URL", value: IOC_URL }),
  report(13, "IpReputation", "suspicious", 6.9, 74, "Known bad ASN", { kind: "IP", value: "203.0.113.77" }),
  report(14, "HashLookup", "malicious", 9.6, 96, "Trojan.Dropper", {
    kind: "HASH",
    value: "9f2b4c7a51e0d3c8a6b7f1e2d4c5a8b9",
  }),
];

const detailFor = (r: Row) => {
  const ioc = r.type === "IOC";
  const reports = ioc ? IOC_REPORTS : MAIL_REPORTS;
  return {
    ...r,
    analyzer_reports: reports,
    case_infos: {
      id: r.id,
      score: 9.5,
      confidence: 94,
      results: r.result,
      classification: "Phishing",
      score_ai: ioc ? null : 9.7,
      confidence_ai: ioc ? null : 94,
      classification_ai: ioc ? "" : "Phishing",
      category_ai: ioc ? null : "Credential harvesting",
      verdict_explanation: VERDICT_MAIL,
    },
    threat_classification: { label: "Phishing", category: "Credential harvesting", source: ioc ? "virustotal" : "ai" },
    analysis_health: { total: reports.length, failed: 0, pending: 0, failures: [] },
    challenge_proposed_result: "",
    challenge_reason: "",
    reporter_context: ioc ? "Link in an HR payroll email. Looked odd." : "Got this from HR-Payroll, but the link looked odd.",
    reporter_note: "",
    is_allowlisted: false,
    is_denylisted: false,
    list_reason: "",
    url_artifacts: [],
    raw: {
      case: { id: r.id },
      fileOrMail: null,
      nonFileIocs: null,
      analyzer_report_ids: reports.map((x) => x.id),
    },
  };
};

const ANALYZERS = [
  ["AIMailAnalyzer", 1.0],
  ["UrlReputation", 0.9],
  ["YaraRules", 0.7],
  ["MailHeaderInspector", 0.6],
  ["Sandbox", 0.5],
  ["IpReputation", 0.5],
  ["HashLookup", 0.8],
].map(([name, weight], i) => ({
  id: i + 1,
  name,
  weight,
  analyzer_cortex_id: `${name}_1_0`,
  is_active: true,
}));

// ─── Dashboard ──────────────────────────────────────────────────────────────

const now = new Date();

const DASHBOARD = {
  month: now.getUTCMonth() + 1,
  year: now.getUTCFullYear(),
  scope: { key: "ALL", label: "Overall" },
  reports: 248,
  outcomes: { safe: 121, inconclusive: 31, suspicious: 52, dangerous: 37, failure: 2 },
  in_progress: 5,
  by_type: { MAIL: 142, FILE: 31, URL: 49, IP: 12, HASH: 8, IOC: 6, UNKNOWN: 0 },
  reporters: 63,
  new_users: 9,
  previous: {
    reports: 205,
    outcomes: { safe: 104, inconclusive: 27, suspicious: 41, dangerous: 31, failure: 2 },
  },
  trend: [3, 2, 1, 0].map((w, i) => {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - w * 7);
    return { week_start: d.toISOString().slice(0, 10), reports: [48, 61, 57, 82][i] };
  }),
  top_reporters: [
    { label: "Camila Reyes", value: 21 },
    { label: "Jordan Kim", value: 17 },
    { label: "Haruto Sato", value: 14 },
    { label: "Sam Whitfield", value: 11 },
    { label: "Adaeze Okafor", value: 8 },
  ],
};

// ─── Campaigns ──────────────────────────────────────────────────────────────

const dayStr = (daysAgo: number) => {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - daysAgo);
  return d.toISOString().slice(0, 10);
};

const CAMPAIGN_DAYS = Array.from({ length: 15 }, (_, i) => dayStr(14 - i));
const NON_DANGER = [6, 5, 7, 4, 6, 8, 5, 6, 7, 5, 9, 6, 8, 7, 6];
const DANGEROUS = [0, 1, 0, 0, 2, 1, 0, 3, 6, 9, 5, 2, 1, 4, 7];

function pcaPoints() {
  // Deterministic pseudo-random scatter: tight clusters per class.
  let seed = 7;
  const rnd = () => {
    seed = (seed * 16807) % 2147483647;
    return seed / 2147483647 - 0.5;
  };
  const clusters: Array<[string, number, number, number, number, number]> = [
    ["SAFE", -2.2, 0.6, 0.4, 70, 0.9],
    ["UNWANTED", -0.4, -1.4, 0.8, 25, 0.5],
    ["SUSPICIOUS", 1.0, 1.1, -0.9, 28, 0.5],
    ["DANGEROUS", 2.4, -0.5, 1.2, 36, 0.35],
  ];
  const points: unknown[] = [];
  let n = 0;
  for (const [label, cx, cy, cz, count, spread] of clusters) {
    for (let i = 0; i < count; i++) {
      n += 1;
      points.push({
        x: cx + rnd() * spread * 2,
        y: cy + rnd() * spread * 2,
        z: cz + rnd() * spread * 2,
        label,
        suspicious_case_id: String(1000 + n),
        mail_subject: label === "DANGEROUS" ? "Action required: payroll update" : "Message",
        sourceRefs: [],
        date: dayStr(Math.floor((rnd() + 0.5) * 14)),
      });
    }
  }
  return { points, explained_variance: [0.42, 0.23, 0.11] };
}

const CAMPAIGN_SUMMARY = {
  days: 15,
  period: { start: dayStr(14), end: dayStr(0) },
  messages: 187,
  previous_messages: 154,
  dangerous: 37,
  previous_dangerous: 22,
  dangerous_share: 0.198,
  previous_dangerous_share: 0.143,
  peak_day: { date: dayStr(5), count: 15 },
  mix: { SAFE: 96, UNWANTED: 18, SUSPICIOUS: 36, DANGEROUS: 37 },
  unclassified: 0,
  campaigns: [
    {
      name: "Payroll update credential lure",
      first_seen: iso(6),
      last_seen: iso(0, 8, 41),
      messages: 19,
      dangerous: 17,
      dangerous_share: 0.89,
      sample_subject: "Action required: payroll update for October",
      case_ids: ["1100", "1098", "1095"],
      active: true,
    },
    {
      name: "Parcel delivery smishing wave",
      first_seen: iso(9),
      last_seen: iso(3),
      messages: 11,
      dangerous: 6,
      dangerous_share: 0.55,
      sample_subject: "Your parcel could not be delivered",
      case_ids: ["1090", "1088"],
      active: false,
    },
    {
      name: "Fake invoice macro documents",
      first_seen: iso(12),
      last_seen: iso(1),
      messages: 8,
      dangerous: 8,
      dangerous_share: 1,
      sample_subject: "Invoice Q3 attached",
      case_ids: ["1070"],
      active: false,
    },
  ],
  active_window_hours: 72,
  active_campaigns: 1,
  largest_campaign: { name: "Payroll update credential lure", messages: 19 },
};

// ─── Plumbing ───────────────────────────────────────────────────────────────

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

const matches = (r: Row, q: string) =>
  [String(r.id), r.artifact, r.type, r.result, r.reporter_email].some((v) => v.toLowerCase().includes(q));

/** Honour ?search= so typing in the list's search box visibly filters rows. */
const filtered = (rows: Row[], url: URL) => {
  const q = (url.searchParams.get("search") ?? url.searchParams.get("q") ?? "").trim().toLowerCase();
  return q ? rows.filter((r) => matches(r, q)) : rows;
};

const page_ = (results: unknown[]) => ({ count: results.length, next: null, previous: null, results });

export type DemoState = {
  authenticated: boolean;
  submitted: boolean;
  /** Editable allow/deny lists of the Settings page, keyed by section. */
  lists: Record<string, Array<{ id: string; value: string; created_at?: string }>>;
};

export const newState = (over: Partial<DemoState> = {}): DemoState => ({
  authenticated: false,
  submitted: false,
  lists: {
    domains_allow: [
      { id: "a1", value: "meridian.example" },
      { id: "a2", value: "hr-portal.meridian.example" },
    ],
    domains_deny: [{ id: "d1", value: "meridian-sso-verify.example" }],
  },
  ...over,
});

export async function installMocks(page: Page, state: DemoState) {
  // Per-deployment branding. index.html loads /env-config.js, which assigns
  // window.__ENV__ (src/lib/runtimeEnv.ts) — answer it with Meridian's values.
  await page.route("**/env-config.js", (route) =>
    route.fulfill({
      contentType: "text/javascript",
      body: `window.__ENV__ = ${JSON.stringify({
        VITE_COMPANY_NAME: "Meridian Group",
        VITE_COMPANY_LINK: "https://www.meridian.example",
        VITE_SUPPORT_EMAIL: "security@meridian.example",
        VITE_SUSPICIOUS_EMAIL: "suspicious@meridian.example",
        VITE_GITHUB_REPO_URL: "https://github.com/thalesgroup-cert/suspicious",
      })};`,
    }),
  );
  // Predicate (not a glob): Vite also serves source modules from /src/api/.
  await page.route((u) => u.pathname.startsWith("/api/"), async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname.replace(/^\/api/, "");
    const method = req.method();

    // ── auth
    if (path === "/auth/me/") {
      return state.authenticated
        ? json(route, USER)
        : json(route, { detail: "Not authenticated." }, 401);
    }
    if (path === "/auth/login/" && method === "POST") {
      state.authenticated = true;
      return json(route, { expiry: null, user: USER });
    }
    if (path === "/auth/logout/") {
      state.authenticated = false;
      return json(route, {});
    }
    if (path.startsWith("/profile/")) {
      // Echo writes back so toggles and pickers keep their new value.
      const body = method === "GET" ? {} : JSON.parse(req.postData() ?? "{}");
      return json(route, { ...PROFILE, ...body });
    }

    // ── settings (admin console)
    const list = path.match(/^\/settings\/list\/([a-z_]+)\/(?:([^/]+)\/)?$/);
    if (list) {
      const [, section, id] = list;
      const items = (state.lists[section] ??= []);
      if (method === "POST") {
        const { values = [] } = JSON.parse(req.postData() ?? "{}") as { values?: string[] };
        const created = values.map((value) => {
          const item = { id: String(Date.now() + Math.random()), value, created_at: new Date().toISOString() };
          items.unshift(item);
          return item.id;
        });
        return json(route, { created, duplicates: [], watcher_conflicts: [] }, 201);
      }
      if (method === "DELETE") {
        state.lists[section] = items.filter((i) => i.id !== id);
        return json(route, {});
      }
      return json(route, page_(items));
    }
    if (path === "/settings/email-feeder/") return json(route, { enabled: true });
    if (path === "/settings/analyzers/") return json(route, page_(ANALYZERS));
    if (/^\/settings\/analyzers\/\d+\/$/.test(path)) return json(route, {});
    if (path === "/feeder/health/") {
      return json(route, {
        online: true,
        last_successful_poll: Math.floor(Date.now() / 1000) - 42,
        emails_processed_total: 1284,
        errors_total: 0,
        stale_seconds: 42,
        stale: false,
        checked_at: Math.floor(Date.now() / 1000),
        error: null,
        feeder_status: "ok",
        checks: {
          imap: { ok: true, configured: 2, healthy: 2, last_ok: {} },
          minio: { ok: true, last_ok: Math.floor(Date.now() / 1000) - 42 },
        },
      });
    }

    // ── home
    if (path === "/home/summary/") {
      return json(route, {
        show_scope_modal: false,
        monthly: { everyone_items: 248, user_items: 12, scope_items: 248, scope_name: "Overall" },
        danger_counts: { safe: 121, inconclusive: 31, suspicious: 52, dangerous: 37 },
        scope_danger_counts: null,
        suggested_scopes: {},
        spotlight: {
          title: "Spot it. Report it.",
          description: "Forward anything suspicious to the monitored mailbox — or submit it right here.",
          cta_label: "Submit now",
          cta_path: "/submit",
        },
      });
    }

    // ── submit
    if (path === "/submit/config/") {
      return json(route, {
        status: "success",
        data: { suspicious_email: "suspicious@meridian.example", max_file_bytes: 26214400, max_indicators: 200 },
      });
    }
    if (path === "/submit/indicators/" && method === "POST") {
      state.submitted = true;
      return json(
        route,
        { status: "success", case_id: NEW_CASE_ID, observable_count: 3, accepted: true, skipped: [] },
        201,
      );
    }

    // ── submissions (reporter view)
    const subDetail = path.match(/^\/submissions\/(\d+)\/$/);
    if (subDetail) {
      const id = Number(subDetail[1]);
      const r = id === NEW_CASE_ID ? NEW_ROW : ROWS.find((x) => x.id === id) ?? ROWS[0];
      return json(route, detailFor(r));
    }
    if (path === "/submissions/") {
      const rows = state.submitted ? [NEW_ROW, ...ROWS] : ROWS;
      return json(route, page_(filtered(rows, url)));
    }

    // ── investigations (CERT view)
    const invDetail = path.match(/^\/investigations\/(\d+)\/$/);
    if (invDetail) {
      const id = Number(invDetail[1]);
      const r = id === NEW_CASE_ID ? NEW_ROW : ROWS.find((x) => x.id === id) ?? ROWS[0];
      return json(route, detailFor(r));
    }
    if (path === "/investigations/") {
      const rows = state.submitted ? [NEW_ROW, ...ROWS] : ROWS;
      return json(route, page_(filtered(rows, url)));
    }
    if (path.startsWith("/cases/") && path.endsWith("/comments/")) return json(route, []);

    // ── dashboard
    if (path === "/dashboard/summary/") return json(route, DASHBOARD);
    if (path === "/dashboard/scopes/") {
      return json(route, { default: "ALL", options: [{ key: "ALL", label: "Overall" }] });
    }

    // ── campaigns
    if (path === "/campaigns/classification-counts/") {
      return json(route, { SAFE: 96, UNWANTED: 18, SUSPICIOUS: 36, DANGEROUS: 37 });
    }
    if (path === "/campaigns/pca/") return json(route, pcaPoints());
    if (path === "/campaigns/mail-volume/") {
      return json(route, {
        dates: CAMPAIGN_DAYS,
        non_danger: NON_DANGER,
        dangerous: DANGEROUS,
        campaigns: [{ name: "Payroll update credential lure", start: dayStr(6), end: dayStr(0) }],
      });
    }
    if (path === "/campaigns/summary/") return json(route, CAMPAIGN_SUMMARY);
    if (path === "/campaigns/neighbours/") {
      return json(route, {
        k: 5,
        bad_share_threshold: 0.6,
        novelty_percentile: 95,
        novel_window_days: 7,
        near_known_bad: [],
        novel: [],
      });
    }

    // ── anything else: empty-but-valid
    if (method === "GET") return json(route, path.endsWith("/") && /s\/$/.test(path) ? page_([]) : {});
    return json(route, {});
  });
}
