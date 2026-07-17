import { Stack, Switch, TextField, Typography } from "@mui/material";
import type { ConfigField } from "./connectors";

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
