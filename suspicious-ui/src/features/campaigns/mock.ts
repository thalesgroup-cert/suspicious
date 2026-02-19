import type { ClassificationCounts, MailVolumeResponse, PcaResponse } from "./api";

function rand(n: number) {
  return Math.random() * n;
}

export function mockCounts(): ClassificationCounts {
  return { SAFE: 320, UNWANTED: 95, DANGEROUS: 34, SUSPICIOUS: 22, UNKNOWN: 12 };
}

export function mockPca(): PcaResponse {
  const labels = ["SAFE", "UNWANTED", "DANGEROUS", "SUSPICIOUS", "UNKNOWN"] as const;

  const points = Array.from({ length: 900 }, (_, i) => {
    const label = labels[Math.floor(rand(labels.length))];
    // clusters
    const cx = label === "DANGEROUS" ? 3 : label === "SAFE" ? -3 : rand(2) - 1;
    const cy = label === "DANGEROUS" ? 2 : label === "SAFE" ? -2 : rand(2) - 1;

    const sourceRefs =
      label === "DANGEROUS"
        ? ["Camp-A", "Camp-B"]
        : label === "UNWANTED"
          ? ["Camp-C"]
          : [];

    return {
      x: cx + (rand(1.4) - 0.7),
      y: cy + (rand(1.2) - 0.6),
      label,
      suspiciousCaseId: i + 1000,
      sourceRefs,
    };
  });

  return { points, explained_variance: [0.42, 0.18] };
}

export function mockMailVolume(): MailVolumeResponse {
  const today = new Date();
  const dates: string[] = [];
  const non_danger: number[] = [];
  const dangerous: number[] = [];

  for (let i = 14; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    const iso = d.toISOString().slice(0, 10);
    dates.push(iso);
    non_danger.push(Math.round(20 + rand(40)));
    dangerous.push(Math.round(rand(18)));
  }

  return {
    dates,
    non_danger,
    dangerous,
    campaigns: [
      { name: "Camp-A", start: dates[2] + "T10:00:00Z", end: dates[5] + "T20:00:00Z" },
      { name: "Camp-C", start: dates[8] + "T00:00:00Z", end: dates[10] + "T12:00:00Z" },
    ],
  };
}
