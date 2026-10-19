export type WeightRow = { id: number; weight: number; is_active: boolean };

// Weights live on a 0.1 grid; rounding before summing keeps 0.1 + 0.2 from being 0.30000000000000004.
export const round1 = (n: number) => Math.round(n * 10) / 10;
export const clampWeight = (n: number) => round1(Math.min(1, Math.max(0, n)));

/** Share of the total over every listed analyzer, as the page shows it. */
export function shares(rows: WeightRow[]): Map<number, number> {
  const total = rows.reduce((sum, r) => sum + round1(r.weight), 0);
  return new Map(rows.map((r) => [r.id, total > 0 ? round1(r.weight) / total : 0]));
}

/** Only active analyzers are scheduled, so only they count towards the scoring divisor. */
export function activeSum(rows: WeightRow[]): number {
  return round1(rows.reduce((sum, r) => (r.is_active ? sum + round1(r.weight) : sum), 0));
}

export const wouldZeroTotal = (rows: WeightRow[]): boolean => activeSum(rows) === 0;

/** The total is passed so an all-zero list reads "-" rather than a misleading 0%. */
export function formatShare(share: number, total: number): string {
  return total > 0 ? `${Math.round(share * 100)}%` : "-";
}

export const valueText = (weight: number, share: number): string =>
  `${weight.toFixed(1)}, ${Math.round(share * 100)}% of the total`;
