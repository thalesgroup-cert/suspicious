import type { SubmissionsResponse, SubmissionRow } from "./api";

function isoDaysAgo(n: number) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString();
}

const rows: SubmissionRow[] = [
  {
    id: 10421,
    status: "DONE",
    info: "invoice_2026_02.pdf",
    created_at: isoDaysAgo(1),
    tests_done: 12,
    type: "FILE",
    result: "SAFE",
    is_challengeable: true,
    is_challenged: false,
  },
  {
    id: 10420,
    status: "IN_PROGRESS",
    info: "Subject: Urgent action required",
    created_at: isoDaysAgo(2),
    tests_done: 5,
    type: "MAIL",
    result: "SUSPICIOUS",
    is_challengeable: false,
    is_challenged: false,
  },
  {
    id: 10419,
    status: "DONE",
    info: "http://example.bad-domain.tld/login",
    created_at: isoDaysAgo(3),
    tests_done: 9,
    type: "URL",
    result: "DANGEROUS",
    is_challengeable: true,
    is_challenged: true,
  },
  {
    id: 10418,
    status: "FAILED",
    info: "8.8.8.8",
    created_at: isoDaysAgo(4),
    tests_done: 0,
    type: "IP",
    result: "FAILURE",
    is_challengeable: false,
    is_challenged: false,
  },
];

export function mockMySubmissions(): SubmissionsResponse {
  return { items: rows };
}
