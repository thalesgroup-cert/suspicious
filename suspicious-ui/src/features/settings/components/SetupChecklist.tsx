import { Box, Button, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import WarningAmber from "@mui/icons-material/WarningAmber";

import { fieldLabel } from "@/features/settings/labels";
import { useMuted } from "@/features/settings/useMuted";
import type { ConfigField } from "@/features/settings/components/connectors";
import { focusField } from "@/features/settings/components/focusField";
import { useToneColor } from "@/features/settings/components/useToneColor";

/** What is still needed before the connector counts as connected, with a button per setting that jumps to its field. */
export function SetupChecklist({ missing, total }: { missing: ConfigField[]; total: number }) {
  const theme = useTheme();
  const muted = useMuted();
  const toneColor = useToneColor();
  if (missing.length === 0) return null;
  return (
    <Box
      role="group"
      aria-label="Setup checklist"
      sx={{ mb: 3, p: 2, border: 1, borderColor: "divider", borderRadius: 2, bgcolor: alpha(theme.palette.text.primary, 0.03) }}
    >
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
        <WarningAmber aria-hidden sx={{ fontSize: 20, color: toneColor("warning", 3) }} />
        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
          {missing.length} of {total} required settings missing
        </Typography>
      </Stack>
      <Typography variant="caption" sx={{ display: "block", mt: 0.5, color: muted }}>
        Fill these in and save to finish setting up this connector.
      </Typography>
      <Stack component="ul" direction="row" useFlexGap sx={{ listStyle: "none", m: 0, mt: 1.5, p: 0, flexWrap: "wrap", gap: 1 }}>
        {missing.map((f) => (
          <li key={f.key}>
            <Button size="small" variant="outlined" onClick={() => focusField(f.key)} sx={{ color: "text.primary", borderColor: "divider" }}>
              {fieldLabel(f)}
            </Button>
          </li>
        ))}
      </Stack>
    </Box>
  );
}
