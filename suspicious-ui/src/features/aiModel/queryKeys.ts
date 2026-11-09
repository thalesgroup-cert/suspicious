/** Root key "ai-model": one invalidation after a write refreshes every tab and the Settings Refresh covers it. */
export const aiModelKeys = {
  all: ["ai-model"] as const,
  status: () => ["ai-model", "status"] as const,
  versions: (p?: object) => ["ai-model", "versions", p ?? {}] as const,
  candidates: (p?: object) => ["ai-model", "candidates", p ?? {}] as const,
  shadow: (p?: object) => ["ai-model", "shadow", p ?? {}] as const,
  reviews: (p?: object) => ["ai-model", "reviews", p ?? {}] as const,
  jobs: (p?: object) => ["ai-model", "jobs", p ?? {}] as const,
  ledger: () => ["ai-model", "ledger"] as const,
  flags: (p?: object) => ["ai-model", "flags", p ?? {}] as const,
  queue: (p?: object) => ["ai-model", "queue", p ?? {}] as const,
};
