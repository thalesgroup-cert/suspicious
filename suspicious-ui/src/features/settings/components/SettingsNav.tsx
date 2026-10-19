import * as React from "react";
import { Box, List, ListItemButton, ListItemText, TextField, Typography, useMediaQuery } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";

import { flatten, readableOnTint } from "@/shared/lib/contrast";
import { useAccent } from "@/features/settings/useAccent";
import { GROUPS, type SectionKey } from "@/features/settings/components/sections";
import { SoftCard } from "@/features/settings/components/cards";

export type SettingsNavProps = {
  active: SectionKey;
  unsaved: ReadonlySet<SectionKey>;
  onNavigate(key: SectionKey): void;
};

/** Screen-reader-only text for the unsaved dot, which colour and shape alone cannot convey. */
const visuallyHidden = {
  position: "absolute",
  width: "1px",
  height: "1px",
  overflow: "hidden",
  clip: "rect(0 0 0 0)",
  whiteSpace: "nowrap",
} as const;

const href = (key: SectionKey) => `/settings/${key}`;

export function SettingsNav({ active, unsaved, onNavigate }: SettingsNavProps) {
  const theme = useTheme();
  const isDesktop = useMediaQuery(theme.breakpoints.up("md"), { noSsr: true });
  const labelId = React.useId();
  const accent = useAccent();
  const paper = theme.palette.background.paper;
  // Accent text on its own 10% tint: the raw accent is under 4.5:1 in several themes.
  const activeText = readableOnTint(flatten(theme.palette.primary.main, paper), flatten(theme.palette.primary.main, paper), 0.1, [paper]);

  if (!isDesktop) {
    return (
      <TextField
        select
        fullWidth
        size="small"
        label="Settings section"
        value={active}
        onChange={(e) => onNavigate(e.target.value as SectionKey)}
        slotProps={{ select: { native: true } }}
      >
        {GROUPS.map((g) => (
          <optgroup key={g.key} label={g.label}>
            {g.sections.map((s) => (
              <option key={s.key} value={s.key}>
                {s.title}
                {unsaved.has(s.key) ? " (unsaved changes)" : ""}
              </option>
            ))}
          </optgroup>
        ))}
      </TextField>
    );
  }

  return (
    <SoftCard sx={{ position: "sticky", top: 16 }}>
      <Box component="nav" aria-label="Settings sections" sx={{ p: 1.5 }}>
        {GROUPS.map((g, i) => (
          <Box key={g.key} sx={{ mt: i === 0 ? 0 : 1.5 }}>
            <Typography
              id={`${labelId}-${g.key}`}
              variant="caption"
              color="text.secondary"
              sx={{ display: "block", px: 1.25, pb: 0.5 }}
            >
              {g.label}
            </Typography>
            <List dense disablePadding aria-labelledby={`${labelId}-${g.key}`}>
              {g.sections.map((s) => {
                const isActive = s.key === active;
                return (
                  <ListItemButton
                    key={s.key}
                    component="a"
                    href={href(s.key)}
                    selected={isActive}
                    aria-current={isActive ? "page" : undefined}
                    onClick={(e: React.MouseEvent) => {
                      // Let the browser handle new-tab and modified clicks.
                      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
                      e.preventDefault();
                      onNavigate(s.key);
                    }}
                    sx={{
                      borderRadius: 2,
                      py: 0.75,
                      "&.Mui-selected": { background: alpha(theme.palette.primary.main, 0.1) },
                    }}
                  >
                    <ListItemText
                      primary={s.title}
                      slotProps={{
                        primary: { sx: { color: isActive ? activeText : undefined, fontWeight: isActive ? 700 : 500 } },
                      }}
                    />
                    {unsaved.has(s.key) && (
                      <>
                        <Box
                          aria-hidden
                          sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: accent.mark, flexShrink: 0 }}
                        />
                        <Box component="span" sx={visuallyHidden}>
                          unsaved changes
                        </Box>
                      </>
                    )}
                  </ListItemButton>
                );
              })}
            </List>
          </Box>
        ))}
      </Box>
    </SoftCard>
  );
}
