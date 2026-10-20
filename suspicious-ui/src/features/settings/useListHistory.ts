import { useInfiniteQuery } from "@tanstack/react-query";

import { fetchListHistory, type EditableListSection } from "@/features/settings/api";

/**
 * Pages of add/remove events for one list. The key sits under ["settings","list",section], so every
 * mutation that invalidates the list also refreshes an open history. Closed, nothing is fetched.
 */
export function useListHistory(section: EditableListSection, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: ["settings", "list", section, "history"],
    queryFn: ({ pageParam }) => fetchListHistory(section, pageParam),
    initialPageParam: 1,
    getNextPageParam: (last, _all, lastPage) => (last.next ? lastPage + 1 : undefined),
    enabled,
    retry: false,
  });
}
