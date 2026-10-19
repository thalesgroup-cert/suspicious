export type BatchResult<T> = { ok: T[]; failed: { item: T; error: unknown }[] };

/**
 * Sequential on purpose: the server load stays what the old await-loops
 * produced. Never throws, so one bad item cannot hide the rest of the result.
 */
export async function runBatch<T>(
  items: T[],
  op: (item: T) => Promise<unknown>,
): Promise<BatchResult<T>> {
  const result: BatchResult<T> = { ok: [], failed: [] };
  for (const item of items) {
    try {
      await op(item);
      result.ok.push(item);
    } catch (error) {
      result.failed.push({ item, error });
    }
  }
  return result;
}

export function summarise(ok: unknown[], failed: unknown[], noun: string): string {
  const base = `${ok.length} of ${ok.length + failed.length} ${noun}`;
  return failed.length ? `${base}, ${failed.length} failed` : base;
}
