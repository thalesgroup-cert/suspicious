import { useId, useState, type ReactNode } from "react";
import { Box, Button, Stack, ToggleButton, ToggleButtonGroup, Typography } from "@mui/material";
import ExpandMore from "@mui/icons-material/ExpandMore";

import { dottedGet } from "@/features/settings/components/configHelpers";
import type { ConfigField } from "@/features/settings/components/connectors";
import { resolveProvider, type ProviderSwitchSpec, splitSchema } from "@/features/settings/connectorPresentation";
import { alpha } from "@mui/material/styles";
import { useAccent } from "@/features/settings/useAccent";
import { useMuted } from "@/features/settings/useMuted";

type Props = {
  spec: ProviderSwitchSpec;
  split: ReturnType<typeof splitSchema>;
  /** Draft when there is one, otherwise the saved config. */
  config: Record<string, unknown>;
  saved: Record<string, unknown>;
  errors: Record<string, string>;
  onChange(field: ConfigField, value: unknown): void;
  renderField(field: ConfigField): ReactNode;
};

/**
 * One segmented control instead of a list of provider fields: only the selected provider's fields are shown, and the other
 * provider's saved values stay in the draft untouched (hidden, never cleared). The raw key stays in the helper text.
 */
export function ProviderSwitch({ spec, split, config, saved, errors, onChange, renderField }: Props) {
  const accent = useAccent();
  const muted = useMuted();
  const helpId = useId();
  const regionId = useId();
  const field = split.switchField!;
  const { selected, state, raw } = resolveProvider(spec, dottedGet(config, spec.key));
  const note =
    state === "unset"
      ? `Not set: ${spec.options.find((o) => o.value === spec.fallback)?.label ?? spec.fallback} is used`
      : state === "unknown"
        ? `Unknown provider '${raw}' is saved; pick one to replace it`
        : null;

  // null = the user has not chosen, so edits and server errors keep the manual fields in view.
  const [chosen, setChosen] = useState<boolean | null>(null);
  const hasEdit = (f: ConfigField) => JSON.stringify(dottedGet(config, f.key)) !== JSON.stringify(dottedGet(saved, f.key));
  const needsAttention = split.manual.some((f) => errors[f.key] || hasEdit(f));
  const manualOpen = chosen ?? needsAttention;

  return (
    <Stack spacing={2.5}>
      <Box>
        <Typography id={`${helpId}-label`} variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
          {spec.label}
        </Typography>
        <ToggleButtonGroup
          exclusive
          fullWidth
          size="small"
          value={selected}
          aria-labelledby={`${helpId}-label`}
          aria-describedby={helpId}
          // Selected = accent tint, accent text and border: the grey default selected state was hard to tell from the unselected one.
          sx={{
            "& .MuiToggleButton-root": { textTransform: "none", color: "text.primary", flex: 1, borderColor: "divider" },
            "& .MuiToggleButton-root.Mui-selected": {
              color: accent.text,
              fontWeight: 600,
              bgcolor: alpha(accent.mark, 0.12),
              borderColor: accent.mark,
              "&:hover": { bgcolor: alpha(accent.mark, 0.18) },
            },
          }}
        >
          {spec.options.map((o) => (
            // onClick, not the group's onChange: pressing the segment that already looks selected (an unset or unknown value) must still save it.
            <ToggleButton
              key={o.value}
              value={o.value}
              onClick={() => onChange(field, o.value)}
              {...(o.value === selected ? { "data-field": field.key } : {})}
            >
              {o.label}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
        <Typography id={helpId} variant="caption" sx={{ display: "block", mt: 0.75, color: errors[field.key] ? "error.main" : muted }}>
          {errors[field.key] ? `${errors[field.key]}. ` : ""}
          {note && <Box component="span">{note}</Box>}
          {note ? ". " : ""}
          Saved as <Box component="span" sx={{ fontFamily: "monospace" }}>{spec.key}</Box>
        </Typography>
      </Box>

      <Stack spacing={2}>{(split.byOption[selected] ?? []).map(renderField)}</Stack>

      {split.manual.length > 0 && (
        <Box>
          <Button
            size="small"
            variant="text"
            aria-expanded={manualOpen}
            aria-controls={regionId}
            onClick={() => setChosen(!manualOpen)}
            endIcon={<ExpandMore sx={{ transform: manualOpen ? "rotate(180deg)" : "none" }} />}
            sx={{ color: accent.text, ml: -1 }}
          >
            {spec.manual.label}
          </Button>
          {/* Always rendered so aria-controls resolves; empty while collapsed. */}
          <Stack id={regionId} spacing={2} sx={{ mt: manualOpen ? 1.5 : 0 }}>
            {manualOpen && (
              <>
                <Typography variant="caption" sx={{ color: muted }}>{spec.manual.note}</Typography>
                {split.manual.map(renderField)}
              </>
            )}
          </Stack>
        </Box>
      )}
    </Stack>
  );
}
