import * as React from "react";
import {
  Box,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { RefreshOutlined } from "@mui/icons-material";
import { useThemeMode } from "@/styles/ThemeStore";
import type { ScopeOption } from "@/features/dashboard/api";
import ScopePicker from "./ScopePicker";
import { monthName } from "@/features/dashboard/format";

export default function OverviewHeader(props: {
  title: string;
  subtitle: string;
  /** One-line explanation under the subtitle (e.g. why only Overall is offered). */
  note?: string;

  month: number;
  year: number;
  onMonthChange: (m: number) => void;
  onYearChange: (y: number) => void;

  /** null while the allowed scopes are loading: the picker appears once known. */
  scopeOptions: ScopeOption[] | null;
  scope: string;
  onScopeChange: (key: string) => void;

  onRefresh: () => void;
}) {
  const years = React.useMemo(() => {
    const y = new Date().getFullYear();
    return Array.from({ length: 7 }, (_, i) => y - 3 + i);
  }, []);

  const { capabilities } = useThemeMode();
  const { effects } = capabilities;

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
      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={1.5}
        sx={{ px: { xs: 2, md: 3 }, py: 1.5, alignItems: { md: "center" }, justifyContent: "space-between" }}
      >
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="pageTitle" component="h1">
            {props.title}
          </Typography>
          <Typography variant="subtitle2" color="text.secondary">
            {props.subtitle}
          </Typography>
          {props.note ? (
            <Typography variant="caption" color="text.secondary" component="p">
              {props.note}
            </Typography>
          ) : null}
        </Box>

        <Stack direction="row" useFlexGap spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
          {props.scopeOptions ? (
            <ScopePicker options={props.scopeOptions} value={props.scope} onChange={props.onScopeChange} />
          ) : null}

          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel id="dashboard-month-label">Month</InputLabel>
            <Select
              labelId="dashboard-month-label"
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

          <FormControl size="small" sx={{ minWidth: 96 }}>
            <InputLabel id="dashboard-year-label">Year</InputLabel>
            <Select
              labelId="dashboard-year-label"
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

          <Tooltip title="Refresh">
            <IconButton
              aria-label="Refresh"
              onClick={props.onRefresh}
              sx={{ borderRadius: 2, border: "1px solid", borderColor: "divider" }}
            >
              <RefreshOutlined />
            </IconButton>
          </Tooltip>
        </Stack>
      </Stack>
    </Box>
  );
}
