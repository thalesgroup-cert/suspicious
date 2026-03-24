// src/app/queryClient.ts
import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // One automatic retry on failure — avoids hammering the server
      // on hard errors but recovers from transient network blips.
      retry: 1,

      // Don't re-fetch just because the user switched tabs.
      refetchOnWindowFocus: false,

      // Data is considered fresh for 30 s. Avoids redundant requests
      // when the same query key is mounted in multiple components.
      staleTime: 30_000,

      // Keep unused query results in cache for 5 minutes.
      gcTime: 5 * 60_000,
    },
    mutations: {
      // Don't retry mutations — they have side effects.
      retry: 0,
    },
  },
});