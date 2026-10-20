import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { testConnector } from "@/features/settings/components/connectors";

export type TestResult = { ok: boolean; text: string };

/** A rejected request (4xx/5xx, network) must not vanish: say what went wrong, with the HTTP status when there is one. */
function testFailureMessage(err: unknown): string {
  const response = (err as { response?: { status?: number; data?: { detail?: unknown; error?: unknown } } }).response;
  const message = response?.data?.detail ?? response?.data?.error;
  if (typeof message === "string" && message) return message;
  return response?.status ? `Connection test failed (HTTP ${response.status}).` : "Connection test failed.";
}

/**
 * One connector's connection test and its latest result; shared by the tile and the drawer so both word it the same way.
 * Pass `store` to keep the result somewhere that outlives the caller (the gallery does, so a tile that a filter removes and brings back still shows it).
 */
export function useConnectorTest(name: string, store?: { result: TestResult | null; set: (r: TestResult | null) => void }) {
  const queryClient = useQueryClient();
  const [own, setOwn] = useState<TestResult | null>(null);
  const result = store ? store.result : own;
  const setResult = store ? store.set : setOwn;
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
