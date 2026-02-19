// src/features/investigation/mock.ts
import type { InvestigationListResponse, InvestigationRow, InvestigationStatus, InvestigationType } from "./api";

function makeMockRows(): InvestigationRow[] {
  const now = Date.now();
  const types: InvestigationType[] = ["MAIL", "FILE", "URL", "IP", "HASH"];
  const statuses: InvestigationStatus[] = ["NEW", "IN_PROGRESS", "DONE", "FAILED", "REJECTED"];
  const results = ["SAFE", "SUSPICIOUS", "INCONCLUSIVE", "DANGEROUS", "MALICIOUS", "UNWANTED", "FAILURE"];

  return Array.from({ length: 64 }, (_, idx) => {
    const i = idx + 1;
    const type = types[i % types.length];
    const status = statuses[i % statuses.length];
    const result = results[i % results.length];
    const created_at = new Date(now - i * 36e5).toISOString();

    const info =
      type === "MAIL"
        ? `Invoice update ${i} — subject line example that can be long long long long long`
        : type === "FILE"
          ? `attachment_${i}.docm`
          : type === "URL"
            ? `https://example-${i}.tld/login`
            : type === "IP"
              ? `192.0.2.${(i % 200) + 1}`
              : `d41d8cd98f00b204e9800998ecf8427e-${i}`;

    return {
      id: 1000 + i,
      reporter_email: `user${(i % 24) + 1}@example.com`,
      reporter_name: `User ${(i % 24) + 1}`,
      status,
      info,
      created_at,
      tests_done: (i % 7) + 1,
      type,
      result,
    };
  });
}

export async function mockInvestigations(): Promise<InvestigationListResponse> {
  return { items: makeMockRows() };
}
