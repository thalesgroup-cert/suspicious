import { useQuery } from "@tanstack/react-query";
import { listAlerts } from "./api";

export function useAlerts() {
  return useQuery({
    queryKey: ["alerts"],
    queryFn: listAlerts,
    staleTime: 10_000,
  });
}
