import { useQuery } from "@tanstack/react-query";
import { getFeederHealth, type FeederHealth } from "@/features/settings/api";
import type { StatusTone } from "@/features/settings/components/StatusLabel";

export type FeederTone = "online" | "stale" | "offline" | "loading";

export function feederTone(h: FeederHealth | undefined): FeederTone {
  if (!h) return "loading";
  if (!h.online) return "offline";
  if (h.stale) return "stale";
  return "online";
}

/** One shared query: the status strip badge and the feeder panel read the same cache entry, so only one request runs. */
export function useFeederHealth(enabled = true) {
  return useQuery<FeederHealth>({
    queryKey: ["feeder", "health"],
    queryFn: getFeederHealth,
    enabled,
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
    retry: false,
    staleTime: 15_000,
  });
}

const HEALTH_LABEL: Record<FeederTone, { tone: StatusTone; label: string }> = {
  online: { tone: "ok", label: "Online" },
  stale: { tone: "warning", label: "Stale" },
  offline: { tone: "danger", label: "Offline" },
  loading: { tone: "neutral", label: "Checking" },
};

/** Icon + word for the runtime health; a failed read says so instead of staying on "Checking" forever. */
export function feederHealthStatus(q: { data?: FeederHealth; isError: boolean }): { tone: StatusTone; label: string } {
  return q.isError ? { tone: "neutral", label: "Status unavailable" } : HEALTH_LABEL[feederTone(q.data)];
}
