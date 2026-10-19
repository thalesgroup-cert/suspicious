import { useQuery } from "@tanstack/react-query";
import { getFeederHealth, type FeederHealth } from "@/features/settings/api";

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
