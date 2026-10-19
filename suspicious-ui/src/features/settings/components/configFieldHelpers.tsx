import { Box, InputAdornment, Stack, Switch, TextField, Typography } from "@mui/material";
import { fieldLabel } from "@/features/settings/labels";
import { StatusLabel } from "./StatusLabel";
import type { ConfigField } from "./connectors";

// The raw key stays visible so an operator can match the field to the config file.
function Help({ text, fieldKey, error }: { text?: string; fieldKey: string; error?: string }) {
  return (
    <>
      {error ? `${error}. ` : ""}
      {text ? `${text} ` : ""}
      <Box component="span" sx={{ fontFamily: "monospace" }}>
        {fieldKey}
      </Box>
    </>
  );
}

/** The config API returns this mask for a stored secret instead of the value. */
export const SECRET_MASK = "********";

export function ConfigFieldInput({
  field,
  value,
  onChange,
  error,
  secretIsSet,
}: {
  field: ConfigField;
  value: unknown;
  onChange: (v: unknown) => void;
  error?: string;
  /** Whether a secret is stored. Defaults to reading the mask from `value`; pass it when `value` is a draft. */
  secretIsSet?: boolean;
}) {
  const label = fieldLabel(field);
  if (field.type === "secret") {
    const isSet = secretIsSet ?? value === SECRET_MASK;
    return (
      <TextField
        size="small"
        fullWidth
        type="password"
        label={label}
        value={typeof value === "string" && value !== SECRET_MASK ? value : ""}
        placeholder={SECRET_MASK}
        error={Boolean(error)}
        helperText={<Help text="Leave blank to keep the current secret" fieldKey={field.key} error={error} />}
        autoComplete="new-password"
        onChange={(e) => onChange(e.target.value)}
        slotProps={{
          input: {
            // Beside the box, not in the helper text, so a screen reader meets it with the field.
            endAdornment: (
              <InputAdornment position="end">
                <StatusLabel size="small" tone={isSet ? "ok" : "neutral"} label={isSet ? "Set" : "Not set"} />
              </InputAdornment>
            ),
          },
        }}
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
          <Typography variant="caption" color={error ? "error" : "text.secondary"} sx={{ display: "block" }}>
            <Help text={field.help} fieldKey={field.key} error={error} />
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
      error={Boolean(error)}
      helperText={<Help text={field.help} fieldKey={field.key} error={error} />}
      onChange={(e) =>
        onChange(field.type === "int" ? Number(e.target.value) : e.target.value)
      }
    />
  );
}
