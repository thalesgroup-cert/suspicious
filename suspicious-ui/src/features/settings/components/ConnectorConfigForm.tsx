import { useId, useState } from "react";
import { Box, Button, Stack, Typography } from "@mui/material";
import ExpandMore from "@mui/icons-material/ExpandMore";

import { ConfigFieldInput, SECRET_MASK } from "@/features/settings/components/configFieldHelpers";
import { dottedGet } from "@/features/settings/components/configHelpers";
import type { ConfigField, Connector } from "@/features/settings/components/connectors";
import { groupFields, type FieldGroup } from "@/features/settings/connectorConfig";
import { PROVIDER_SWITCH, splitSchema } from "@/features/settings/connectorPresentation";
import { ProviderSwitch } from "@/features/settings/components/ProviderSwitch";
import { useAccent } from "@/features/settings/useAccent";

type Props = {
  connector: Connector;
  /** Draft when there is one, otherwise the saved config. */
  config: Record<string, unknown>;
  saved: Record<string, unknown>;
  errors: Record<string, string>;
  onChange(field: ConfigField, value: unknown): void;
};

type FormProps = Omit<Props, "connector">;

function fieldInput(f: ConfigField, { config, saved, errors, onChange }: FormProps) {
  return (
    <ConfigFieldInput
      key={f.key}
      field={f}
      value={dottedGet(config, f.key)}
      secretIsSet={dottedGet(saved, f.key) === SECRET_MASK}
      error={errors[f.key]}
      onChange={(v) => onChange(f, v)}
    />
  );
}

function Group({ group, ...form }: FormProps & { group: FieldGroup }) {
  const { config, saved, errors } = form;
  const regionId = useId();
  const accent = useAccent();
  // null = the user has not chosen, so edits and server errors keep optional fields in view.
  const [chosen, setChosen] = useState<boolean | null>(null);
  const hasEdit = (f: ConfigField) => JSON.stringify(dottedGet(config, f.key)) !== JSON.stringify(dottedGet(saved, f.key));
  const needsAttention = group.optional.some((f) => errors[f.key] || hasEdit(f));
  // A group with nothing required would otherwise be a lone collapsed button hiding everything it holds.
  const collapsible = group.required.length > 0 && group.optional.length > 0;
  const open = !collapsible || (chosen ?? needsAttention);

  const input = (f: ConfigField) => fieldInput(f, form);

  return (
    <Box component="fieldset" sx={{ border: 0, m: 0, p: 0, minWidth: 0 }}>
      <Typography component="legend" variant="subtitle2" sx={{ p: 0, mb: 1.5 }}>
        {group.label}
      </Typography>
      <Stack spacing={2}>
        {group.required.map(input)}
        {collapsible && (
          <>
            <Button
              size="small"
              variant="text"
              aria-expanded={open}
              aria-controls={regionId}
              onClick={() => setChosen(!open)}
              endIcon={<ExpandMore sx={{ transform: open ? "rotate(180deg)" : "none" }} />}
              sx={{ alignSelf: "flex-start", color: accent.text }}
            >
              {open ? "Hide" : "Show"} optional settings ({group.optional.length})
            </Button>
            {/* Always rendered so aria-controls resolves; empty while collapsed. */}
            <Stack id={regionId} spacing={2}>
              {open && group.optional.map(input)}
            </Stack>
          </>
        )}
        {!collapsible && group.optional.map(input)}
      </Stack>
    </Box>
  );
}

export function ConnectorConfigForm({ connector, ...rest }: Props) {
  const spec = PROVIDER_SWITCH[connector.name];
  const split = spec ? splitSchema(connector.config_schema, spec) : null;
  // A spec whose switch field is not in the schema (an older backend) falls back to the generic form rather than hiding fields.
  const withSwitch = spec && split?.switchField ? { spec, split } : null;
  const groups = groupFields(withSwitch ? withSwitch.split.rest : connector.config_schema);
  if (groups.length === 0 && !withSwitch) {
    return <Typography variant="body2" color="text.secondary">This connector has no settings.</Typography>;
  }
  return (
    <Stack spacing={3.5} sx={{ maxWidth: 640 }}>
      {withSwitch && <ProviderSwitch {...withSwitch} {...rest} renderField={(f) => fieldInput(f, rest)} />}
      {groups.map((g) => (
        <Group key={g.key} group={g} {...rest} />
      ))}
    </Stack>
  );
}
