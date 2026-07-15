import { Stack, Switch, TextField, Typography } from "@mui/material";
import type { ConfigField } from "./connectors";

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

export function ConfigFieldInput({
  field,
  value,
  onChange,
}: {
  field: ConfigField;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  if (field.type === "secret") {
    return (
      <TextField
        size="small"
        fullWidth
        type="password"
        label={field.key}
        value={typeof value === "string" && value !== "********" ? value : ""}
        placeholder="********"
        helperText="Leave blank to keep the current secret"
        autoComplete="new-password"
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }
  if (field.type === "bool") {
    return (
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
        <Switch checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
        <Typography variant="body2">{field.key}</Typography>
      </Stack>
    );
  }
  return (
    <TextField
      size="small"
      fullWidth
      label={field.key}
      required={field.required}
      type={field.type === "int" ? "number" : "text"}
      value={value ?? ""}
      helperText={field.help}
      onChange={(e) =>
        onChange(field.type === "int" ? Number(e.target.value) : e.target.value)
      }
    />
  );
}
