export function dottedGet(obj: Record<string, unknown>, key: string): unknown {
  return key.split(".").reduce<unknown>(
    (node, part) =>
      node && typeof node === "object" ? (node as Record<string, unknown>)[part] : undefined,
    obj,
  );
}

export function dottedSet(obj: Record<string, unknown>, key: string, value: unknown) {
  const parts = key.split(".");
  let node = obj;
  for (const part of parts.slice(0, -1)) {
    node[part] = (node[part] as Record<string, unknown>) ?? {};
    node = node[part] as Record<string, unknown>;
  }
  node[parts[parts.length - 1]] = value;
}

export function stripUnchangedSecrets(
  cfg: Record<string, unknown>,
  secretKeys: string[],
): Record<string, unknown> {
  const out = structuredClone(cfg);
  for (const key of secretKeys) {
    const current = dottedGet(out, key);
    if (current === "" || current === "********" || current == null) {
      const parts = key.split(".");
      let node: Record<string, unknown> | undefined = out;
      for (const part of parts.slice(0, -1)) {
        node = node?.[part] as Record<string, unknown> | undefined;
        if (!node) break;
      }
      if (node) delete node[parts[parts.length - 1]];
    }
  }
  return out;
}
