import { Box, Stack, Switch, TextField, Typography } from "@mui/material";
import { fieldLabel } from "@/features/settings/labels";
import type { ConfigField } from "./connectors";

// The raw key stays visible so an operator can match the field to the config file.
function Help({ text, fieldKey }: { text?: string; fieldKey: string }) {
  return (
    <>
      {text ? `${text} ` : ""}
      <Box component="span" sx={{ fontFamily: "monospace" }}>
        {fieldKey}
      </Box>
    </>
  );
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
  const label = fieldLabel(field);
  if (field.type === "secret") {
    return (
      <TextField
        size="small"
        fullWidth
        type="password"
        label={label}
        value={typeof value === "string" && value !== "********" ? value : ""}
        placeholder="********"
        helperText={<Help text="Leave blank to keep the current secret" fieldKey={field.key} />}
        autoComplete="new-password"
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }
  if (field.type === "bool") {
    return (
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
        <Switch
          checked={Boolean(value)}
          onChange={(e) => onChange(e.target.checked)}
          slotProps={{ input: { "aria-label": label } }}
        />
        <Box>
          <Typography variant="body2">{label}</Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
            <Help text={field.help} fieldKey={field.key} />
          </Typography>
        </Box>
      </Stack>
    );
  }
  return (
    <TextField
      size="small"
      fullWidth
      label={label}
      required={field.required}
      type={field.type === "int" ? "number" : "text"}
      value={value ?? ""}
      helperText={<Help text={field.help} fieldKey={field.key} />}
      onChange={(e) =>
        onChange(field.type === "int" ? Number(e.target.value) : e.target.value)
      }
    />
  );
}
