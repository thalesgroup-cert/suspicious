import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { testConnector } from "@/features/settings/components/connectors";

export type TestResult = { ok: boolean; text: string };

/** A rejected request (4xx/5xx, network) must not vanish: say what went wrong, with the HTTP status when there is one. */
export function testFailureMessage(err: unknown): string {
  const response = (err as { response?: { status?: number; data?: { detail?: unknown; error?: unknown } } }).response;
  const message = response?.data?.detail ?? response?.data?.error;
  if (typeof message === "string" && message) return message;
  return response?.status ? `Connection test failed (HTTP ${response.status}).` : "Connection test failed.";
}

/** One connector's connection test and its latest result; shared by the tile and the drawer so both word it the same way. */
export function useConnectorTest(name: string) {
  const queryClient = useQueryClient();
  const [result, setResult] = useState<TestResult | null>(null);
  const mutation = useMutation({
    mutationFn: () => {
      setResult(null);
      return testConnector(name);
    },
    onSuccess: (r) => setResult(r.ok ? { ok: true, text: `OK: ${r.detail}` } : { ok: false, text: `Failed: ${r.detail}` }),
    onError: (err) => setResult({ ok: false, text: testFailureMessage(err) }),
    // A test records the connector's health, so the tiles' status and "Last checked" may have changed.
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["connectors"] }),
  });
  return { run: () => mutation.mutate(), pending: mutation.isPending, result, dismiss: () => setResult(null) };
}
