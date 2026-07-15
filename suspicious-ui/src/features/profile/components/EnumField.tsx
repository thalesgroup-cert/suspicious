import * as React from "react";
import { Box, Collapse, Stack, Typography } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { CasinoOutlined, ExpandLessOutlined, ExpandMoreOutlined } from "@mui/icons-material";

export function EnumField({
  label,
  values,
  value,
  onChange,
  onReset,
  renderThumb,
}: {
  label: string;
  values: string[];
  value?: string;
  onChange: (v: string) => void;
  onReset: () => void;
  renderThumb: (v: string) => string;
}) {
  const theme = useTheme();
  const [open, setOpen] = React.useState(false);
  const toggle = () => setOpen((o) => !o);

  return (
    <Stack spacing={0.75}>
      <Stack
        direction="row"
        spacing={1}
        role="button"
        tabIndex={0}
        aria-expanded={open}
        aria-label={`${label} options`}
        onClick={toggle}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            toggle();
          }
        }}
        sx={{ alignItems: "center", cursor: "pointer" }}
      >
        <Typography sx={{ flex: 1, fontWeight: 800, fontSize: 12.5 }}>{label}</Typography>
        <Typography
          variant="caption"
          sx={{ color: value ? "text.primary" : "text.disabled", fontWeight: value ? 800 : 600 }}
        >
          {value ?? "Auto"} · {values.length}
        </Typography>
        {open ? <ExpandLessOutlined fontSize="small" /> : <ExpandMoreOutlined fontSize="small" />}
      </Stack>
      <Collapse in={open} unmountOnExit>
        <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(52px, 1fr))", gap: 0.75, pt: 0.5 }}>
          <Box
            role="button"
            tabIndex={0}
            aria-label={`${label} Auto`}
            aria-pressed={!value}
            onClick={onReset}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onReset();
              }
            }}
            sx={{
              cursor: "pointer",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 0.25,
              p: 0.5,
              borderRadius: 2,
              border: `1px solid ${!value ? theme.palette.primary.main : alpha(theme.palette.divider, 0.5)}`,
            }}
          >
            <CasinoOutlined fontSize="small" />
            <Typography variant="caption" sx={{ fontSize: 9.5, fontWeight: 700 }}>Auto</Typography>
          </Box>
          {values.map((v) => {
            const selected = value === v;
            return (
              <Box
                key={v}
                role="button"
                tabIndex={0}
                aria-label={`${label} ${v}`}
                aria-pressed={selected}
                onClick={() => onChange(v)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onChange(v);
                  }
                }}
                sx={{
                  cursor: "pointer",
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: 0.25,
                  p: 0.5,
                  borderRadius: 2,
                  border: `1px solid ${selected ? theme.palette.primary.main : alpha(theme.palette.divider, 0.5)}`,
                }}
              >
                <Box component="img" src={renderThumb(v)} alt={v} sx={{ width: 32, height: 32 }} />
                <Typography
                  variant="caption"
                  noWrap
                  sx={{ fontSize: 9.5, fontWeight: selected ? 900 : 700, maxWidth: 48 }}
                >
                  {v}
                </Typography>
              </Box>
            );
          })}
        </Box>
      </Collapse>
    </Stack>
  );
}
