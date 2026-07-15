import * as React from "react";
import { Box, IconButton, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { RestartAltOutlined } from "@mui/icons-material";

export function ColorField({
  label,
  palette,
  value,
  onChange,
  onReset,
}: {
  label: string;
  palette: string[];
  value?: string;
  onChange: (hex: string) => void;
  onReset: () => void;
}) {
  const theme = useTheme();
  const inputRef = React.useRef<HTMLInputElement>(null);

  return (
    <Stack spacing={0.75}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
        <Typography sx={{ flex: 1, fontWeight: 800, fontSize: 12.5 }}>{label}</Typography>
        <IconButton
          size="small"
          aria-label={`${label} use random`}
          onClick={onReset}
          disabled={!value}
          sx={{ opacity: value ? 1 : 0.35 }}
        >
          <RestartAltOutlined fontSize="small" />
        </IconButton>
      </Stack>
      <Stack direction="row" spacing={0.75} sx={{ flexWrap: "wrap" }}>
        {palette.map((hex) => {
          const selected = value === hex;
          return (
            <Box
              key={hex}
              role="button"
              tabIndex={0}
              aria-label={`${label} ${hex}`}
              aria-pressed={selected}
              onClick={() => onChange(hex)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") onChange(hex);
              }}
              sx={{
                width: 26,
                height: 26,
                borderRadius: "50%",
                cursor: "pointer",
                bgcolor: `#${hex}`,
                border: selected
                  ? `2px solid ${theme.palette.primary.main}`
                  : `2px solid ${alpha(theme.palette.divider, 0.4)}`,
                boxShadow: selected ? `0 0 0 2px ${alpha(theme.palette.primary.main, 0.3)}` : "none",
                transition: "all .15s ease",
              }}
            />
          );
        })}
        <Box
          onClick={() => inputRef.current?.click()}
          sx={{
            width: 26,
            height: 26,
            borderRadius: "50%",
            cursor: "pointer",
            border: `1.5px dashed ${alpha(theme.palette.text.secondary, 0.5)}`,
            display: "grid",
            placeItems: "center",
            position: "relative",
            overflow: "hidden",
            fontSize: 13,
            color: "text.secondary",
          }}
        >
          +
          <Box
            ref={inputRef}
            component="input"
            type="color"
            value={`#${value ?? palette[0] ?? "000000"}`}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              onChange(e.target.value.slice(1).toLowerCase())
            }
            aria-label={`${label} custom color`}
            sx={{
              position: "absolute",
              inset: 0,
              opacity: 0,
              cursor: "pointer",
              width: "100%",
              height: "100%",
              border: "none",
              padding: 0,
            }}
          />
        </Box>
      </Stack>
    </Stack>
  );
}
