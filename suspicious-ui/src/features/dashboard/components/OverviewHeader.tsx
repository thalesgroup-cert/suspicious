// file: src/features/dashboard/components/OverviewHeader.tsx
import * as React from "react";
import {
  Box,
  Chip,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Popover,
  Select,
  Skeleton,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { RefreshOutlined, SettingsOutlined } from "@mui/icons-material";
import { useThemeMode } from "@/styles/ThemeStore";

function monthName(m: number) {
  return new Date(2000, m - 1, 1).toLocaleString("en", { month: "long" });
}

export default function OverviewHeader(props: {
  title: string;
  subtitle: string;

  isElevated: boolean;
  isCiso: boolean;

  month: number;
  year: number;
  scope: string;
  cisoScope?: string;

  onMonthChange: (m: number) => void;
  onYearChange: (y: number) => void;
  onScopeChange: (s: string) => void;

  onRefresh: () => void;
  refreshing: boolean;

  // ✅ new
  trendWindow: number;
  onTrendWindowChange: (n: number) => void;
}) {
  const now = new Date();
  const years = React.useMemo(() => Array.from({ length: 7 }, (_, i) => now.getFullYear() - 3 + i), [now]);

  const [anchorEl, setAnchorEl] = React.useState<HTMLElement | null>(null);
  const open = Boolean(anchorEl);

  const { capabilities } = useThemeMode();
  const { effects } = capabilities;

  // Sticky bar border glow for themed sidebars
  const barGlow = React.useMemo(() => {
    if (effects.hasNeonEffect)
      return "0 1px 0 rgba(0,229,255,.25), 0 4px 24px rgba(0,229,255,.06)";
    if (effects.hasSolarEffect)
      return "0 1px 0 rgba(201,164,76,.22), 0 4px 24px rgba(201,164,76,.06)";
    if (effects.hasPortalEffect)
      return "0 1px 0 rgba(74,144,217,.22), 0 4px 24px rgba(74,144,217,.06)";
    if (effects.hasAlertStates)
      return "0 1px 0 rgba(55,214,199,.18), 0 4px 24px rgba(55,214,199,.04)";
    return undefined;
  }, [effects]);

  return (
    <Box
      sx={{
        position: "sticky",
        top: 0,
        zIndex: 20,
        borderBottom: "1px solid",
        borderColor: "divider",
        backdropFilter: "blur(14px)",
        boxShadow: barGlow,
      }}
    >
      <Box sx={{ px: { xs: 2, md: 3 }, py: 1.5 }}>
        <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={2}>
          <Box>
            <Typography
              variant="h5"
              sx={{ fontWeight: 950, letterSpacing: -0.4, lineHeight: 1.1 }}
            >
              {props.title}
            </Typography>
          </Box>

          <Stack direction="row" spacing={1} alignItems="center">
            <Tooltip title="Refresh">
              <span>
                <IconButton
                  aria-label="Refresh"
                  onClick={props.onRefresh}
                  sx={{ borderRadius: 2, border: "1px solid", borderColor: "divider" }}
                >
                  <RefreshOutlined />
                </IconButton>
              </span>
            </Tooltip>

            {props.isElevated ? (
              <>
                <Tooltip title="Time & scope">
                  <IconButton
                    aria-label="Time & scope"
                    onClick={(e) => setAnchorEl(e.currentTarget)}
                    sx={{ borderRadius: 2, border: "1px solid", borderColor: "divider" }}
                  >
                    <SettingsOutlined />
                  </IconButton>
                </Tooltip>

                <Popover
                  open={open}
                  anchorEl={anchorEl}
                  onClose={() => setAnchorEl(null)}
                  anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                  transformOrigin={{ vertical: "top", horizontal: "right" }}
                  PaperProps={{
                    sx: {
                      mt: 1,
                      borderRadius: 3,
                      border: "1px solid",
                      borderColor: "divider",
                      width: 320,
                      p: 1.5,
                    },
                  }}
                >
                  <Stack spacing={1.5}>
                    <Typography sx={{ fontWeight: 900, fontSize: 14 }}>Time & scope</Typography>

                    <FormControl fullWidth size="small">
                      <InputLabel id="month-label">Month</InputLabel>
                      <Select
                        labelId="month-label"
                        label="Month"
                        value={props.month}
                        onChange={(e) => props.onMonthChange(Number(e.target.value))}
                      >
                        {Array.from({ length: 12 }, (_, i) => i + 1).map((m) => (
                          <MenuItem key={m} value={m}>
                            {monthName(m)}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>

                    <FormControl fullWidth size="small">
                      <InputLabel id="year-label">Year</InputLabel>
                      <Select
                        labelId="year-label"
                        label="Year"
                        value={props.year}
                        onChange={(e) => props.onYearChange(Number(e.target.value))}
                      >
                        {years.map((y) => (
                          <MenuItem key={y} value={y}>
                            {y}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>

                    {props.isCiso ? (
                      <FormControl fullWidth size="small">
                        <InputLabel id="scope-label">Scope</InputLabel>
                        <Select
                          labelId="scope-label"
                          label="Scope"
                          value={props.scope}
                          onChange={(e) => props.onScopeChange(String(e.target.value))}
                        >
                          <MenuItem value="ALL">Everyone</MenuItem>
                          {props.cisoScope ? <MenuItem value={props.cisoScope}>{props.cisoScope}</MenuItem> : null}
                        </Select>
                      </FormControl>
                    ) : null}

                    {/* ✅ new */}
                    <FormControl fullWidth size="small">
                      <InputLabel id="trend-label">Trend window</InputLabel>
                      <Select
                        labelId="trend-label"
                        label="Trend window"
                        value={props.trendWindow}
                        onChange={(e) => props.onTrendWindowChange(Number(e.target.value))}
                      >
                        <MenuItem value={1}>1 month</MenuItem>
                        <MenuItem value={3}>3 months</MenuItem>
                        <MenuItem value={6}>6 months</MenuItem>
                        <MenuItem value={12}>12 months</MenuItem>
                      </Select>
                    </FormControl>

                    <Box sx={{ fontSize: 12, color: "text.secondary" }}>
                      Changes apply immediately and refetch the summary.
                    </Box>
                  </Stack>
                </Popover>
              </>
            ) : null}
          </Stack>
        </Stack>
      </Box>
    </Box>
  );
}

export function OverviewHeaderSkeleton() {
  return (
    <Box sx={{ px: { xs: 2, md: 3 }, py: 2 }}>
      <Skeleton width={180} height={36} />
      <Skeleton width={260} height={20} />
    </Box>
  );
}
