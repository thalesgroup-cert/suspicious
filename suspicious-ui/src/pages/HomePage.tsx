import * as React from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Grid,
  IconButton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from "@mui/material";
import { alpha } from "@mui/material/styles";
import {
  ApartmentOutlined,
  ManageSearchOutlined,
  OpenInNewOutlined,
  PublicOutlined,
  RocketLaunchOutlined,
  LeaderboardOutlined,
  UploadFileOutlined,
  DonutLargeOutlined,
  HistoryOutlined,
} from "@mui/icons-material";
import { useNavigate, Link as RouterLink } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useTheme } from "@mui/material/styles";
import { useThemeMode, type ThemeCapabilities } from "@/styles/ThemeStore";
import { api } from "@/api/client";
import { getMe, type Me } from "@/api/auth";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
} from "recharts";
import { useResultColors, useStatusColors } from "@/styles/colorStore";

import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";
import FeederHealthBadge from "@/shared/components/FeederHealthBadge";

import { DashboardCard } from "@/features/home/components/DashboardCard";
import { ThemeGreeting } from "@/features/home/components/ThemeGreeting";
import {
  DANGER_COLORS,
  DANGER_ORDER,
  fmtDate,
  short,
  sum,
  type DangerLabel,
} from "@/features/home/utils";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type DangerCounts = {
  safe?: number;
  inconclusive?: number;
  suspicious?: number;
  dangerous?: number;
};

type HomeSummary = {
  show_scope_modal: boolean;
  monthly: {
    everyone_items?: number;
    scope_items?: number;
    scope_name?: string | null;
  };
  danger_counts?: DangerCounts;
  scope_danger_counts?: DangerCounts | null;
  suggested_scopes?: {
    region?: string | null;
    country?: string | null;
    gbu?: string | null;
  };
  spotlight?: {
    title: string;
    description: string;
    cta_label: string;
    cta_path: string;
  };
};

type SubmissionRow = {
  id: number | string;
  status?: string;
  artifact?: string;
  created_at?: string;
  tests_done?: number;
  type?: string;
  result?: string;
};

type SubmissionsResponse = {
  items?: SubmissionRow[];
  results?: SubmissionRow[];
  count?: number;
};

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

async function getHomeSummary(params?: {
  month?: number;
  year?: number;
}): Promise<HomeSummary> {
  const res = await api.get("/home/summary/", { params });
  return res.data;
}

async function setCisoScope(input: { scope: string }): Promise<{ scope: string }> {
  const res = await api.post("/home/ciso/scope/", input);
  return res.data;
}

async function getMyRecentSubmissions(): Promise<SubmissionRow[]> {
  const res = await api.get("/submissions/", {
    params: { mine: 1, page_size: 3, ordering: "-created_at" },
  });
  const data = res.data as SubmissionsResponse | SubmissionRow[];
  if (Array.isArray(data)) return data.slice(0, 3);
  return (data.results ?? data.items ?? []).slice(0, 3);
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function HomePage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const { capabilities } = useThemeMode();
  const resultColors = useResultColors();
  const statusColors  = useStatusColors();

  const cardClass = React.useMemo(() => {
    const { effects } = capabilities;
    if (effects.hasPortalEffect)   return "temporal-arrive";
    if (effects.hasAlertStates)    return "hud-alertable";
    return undefined;
  }, [capabilities]);

  const dangerColors: Record<DangerLabel, string> = React.useMemo(() => ({
    Safe:         resultColors.safe.main,
    Inconclusive: resultColors.inconclusive.main,
    Suspicious:   resultColors.suspicious.main,
    Dangerous:    resultColors.dangerous.main,
    Failure:      statusColors.failure.main, // optional if your data includes failures
  }), [resultColors, statusColors]);
  const BADGE_W = 132;

  const [scopeChoice, setScopeChoice] = React.useState("");

  const now = React.useMemo(() => new Date(), []);
  const currentMonth = now.getMonth() + 1;
  const currentYear = now.getFullYear();

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  const me = meQuery.data;
  const groups = me?.groups ?? [];
  const isCiso = groups.includes("CISO");
  const isElevated = isCiso || groups.includes("CERT");

  const homeQuery = useQuery<HomeSummary>({
    queryKey: ["homeSummary", currentMonth, currentYear],
    queryFn: () => getHomeSummary({ month: currentMonth, year: currentYear }),
    enabled: !!me,
    retry: false,
  });

  const recentQuery = useQuery<SubmissionRow[]>({
    queryKey: ["myRecentSubmissions"],
    queryFn: getMyRecentSubmissions,
    enabled: !!me,
    retry: false,
  });

  const scopeMutation = useMutation({
    mutationFn: setCisoScope,
    onSuccess: () => {
      homeQuery.refetch();
      meQuery.refetch();
    },
  });

  React.useEffect(() => {
    const home = homeQuery.data;
    const dangerous = home?.danger_counts?.dangerous ?? 0;
    const suspicious = home?.danger_counts?.suspicious ?? 0;
    if (!capabilities.effects.hasAlertStates || !home) {
      document.body.removeAttribute("data-alert");
      document.body.removeAttribute("data-caution");
      return;
    }
    if (dangerous > 0) {
      document.body.dataset.alert = "on";
      document.body.removeAttribute("data-caution");
    } else if (suspicious > 0) {
      document.body.dataset.caution = "on";
      document.body.removeAttribute("data-alert");
    } else {
      document.body.removeAttribute("data-alert");
      document.body.removeAttribute("data-caution");
    }
    return () => {
      document.body.removeAttribute("data-alert");
      document.body.removeAttribute("data-caution");
    };
  }, [capabilities.effects.hasAlertStates, homeQuery.data]);

  if (meQuery.isLoading) {
    return (
      <Box sx={{ minHeight: "100vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!me) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Not authenticated.</Alert>
      </Box>
    );
  }

  const home = homeQuery.data;
  const suggested = home?.suggested_scopes ?? {};
  const showScopeModal = Boolean(home?.show_scope_modal && isCiso);

  const fullName = [me.first_name, me.last_name].filter(Boolean).join(" ");
  const displayName = fullName || me.username || "User";

  const everyoneCount = home?.monthly?.everyone_items ?? 0;
  const scopeCount = home?.monthly?.scope_items ?? 0;
  const scopeLabel = home?.monthly?.scope_name || me.ciso_scope || undefined;

  const danger: Required<DangerCounts> = {
    safe: home?.danger_counts?.safe ?? 0,
    inconclusive: home?.danger_counts?.inconclusive ?? 0,
    suspicious: home?.danger_counts?.suspicious ?? 0,
    dangerous: home?.danger_counts?.dangerous ?? 0,
  };

  const donut = (DANGER_ORDER as readonly DangerLabel[])
    .map(label => {
      const key = label.toLowerCase() as keyof DangerCounts;
      const value = (danger[key] ?? 0) as number;
      return { name: label, value, color: dangerColors[label] };
    })
    .filter(d => d.value > 0);

  const donutTotal = sum(donut.map((d) => d.value));
  const donutTotalColor = theme.palette.text.primary;
  const donutLabelColor = theme.palette.text.secondary;

  const recent = recentQuery.data ?? [];

  const orgCount = everyoneCount;
  const myCount = donutTotal;
  const shareNumerator = isCiso ? scopeCount : myCount;
  const sharePct = orgCount > 0 ? Math.round((shareNumerator / orgCount) * 100) : 0;
  const scopeDanger: Required<DangerCounts> | null = home?.scope_danger_counts
    ? {
        safe: home.scope_danger_counts.safe ?? 0,
        inconclusive: home.scope_danger_counts.inconclusive ?? 0,
        suspicious: home.scope_danger_counts.suspicious ?? 0,
        dangerous: home.scope_danger_counts.dangerous ?? 0,
      }
    : null;
  const showScopeVerdicts = isCiso && scopeDanger !== null;

  return (
    <Box sx={{ px: { xs: 2, md: 3 }, pb: 8, pt: 0 }}>
      <Box sx={{ maxWidth: 1280, mx: "auto" }}>

        {/* ---------------------------------------------------------------- */}
        {/* ---------------------------------------------------------------- */}
        <Stack
          direction={{ xs: "column", md: "row" }}
          spacing={1.5}
          sx={{ mb: 2, justifyContent: "space-between", alignItems: { md: "center" } }}
        >
          <Stack direction="row" spacing={1.5} sx={{ minWidth: 0, alignItems: "flex-start" }}>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="h5" noWrap sx={{ fontWeight: 980, letterSpacing: -0.6 }} >
                Welcome, {displayName}
              </Typography>
              <ThemeGreeting caps={capabilities} name={displayName} />
            </Box>
          </Stack>

          {(groups.includes("Admin") || groups.includes("CERT")) ? (
            <FeederHealthBadge />
          ) : null}
        </Stack>

        {homeQuery.isError ? (
          <Box sx={{ mb: 2 }}>
            <Alert severity="error">Home summary unavailable.</Alert>
          </Box>
        ) : null}

        <Grid container spacing={2}>

          {/* -------------------------------------------------------------- */}
          {/* -------------------------------------------------------------- */}
          <Grid size={{ xs: 12, md: 7 }}>
            <DashboardCard
              title="Threat distribution"
              icon={
                <DonutLargeOutlined
                  sx={
                    capabilities.effects.hasAlertStates
                      ? { animation: "radarSweep 4s linear infinite", transformOrigin: "center" }
                      : capabilities.effects.hasEmberEffect
                      ? { animation: "leafSway 4s ease-in-out infinite", display: "block" }
                      : capabilities.effects.hasBloomEffect
                      ? { animation: "dewPulse 3s ease-in-out infinite", display: "block" }
                      : undefined
                  }
                />
              }
              right={<Chip size="small" label="Monthly" variant="outlined" />}
              className={cardClass}
              titleBadge={
                capabilities.effects.hasAlertStates && danger.dangerous > 0 ? (
                  <Box
                    component="span"
                    aria-label="ALERT"
                    sx={{
                      display: "inline-flex",
                      alignItems: "center",
                      justifyContent: "center",
                      width: 18, height: 18,
                      borderRadius: "3px",
                      fontSize: 11,
                      fontWeight: 900,
                      fontFamily: '"IBM Plex Mono", monospace',
                      backgroundColor: "var(--mgs-alert, #E1061B)",
                      color: "#fff",
                      ml: 0.75,
                      flexShrink: 0,
                      animation: "exclamation 300ms cubic-bezier(.34,1.56,.64,1) both",
                    }}
                  >
                    !
                  </Box>
                ) : capabilities.effects.hasAlertStates && danger.suspicious > 0 ? (
                  <Box
                    component="span"
                    aria-label="CAUTION"
                    sx={{
                      display: "inline-flex",
                      alignItems: "center",
                      justifyContent: "center",
                      width: 18, height: 18,
                      borderRadius: "3px",
                      fontSize: 11,
                      fontWeight: 900,
                      fontFamily: '"IBM Plex Mono", monospace',
                      backgroundColor: "var(--mgs-caution, #F2C94C)",
                      color: "#000",
                      ml: 0.75,
                      flexShrink: 0,
                      animation: "exclamation 300ms cubic-bezier(.34,1.56,.64,1) both",
                    }}
                  >
                    ?
                  </Box>
                ) : null
              }
            >
              <Box
                sx={{ height: 220 }}
                className={capabilities.effects.hasHeatEffect ? "sun-orb" : undefined}
              >
                {homeQuery.isLoading ? (
                  <Stack sx={{ height: "100%", alignItems: "center", justifyContent: "center" }}>
                    <CircularProgress size={22} />
                  </Stack>
                ) : donut.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={donut}
                        dataKey="value"
                        nameKey="name"
                        innerRadius={62}
                        outerRadius={86}
                        isAnimationActive={false}
                        stroke="rgba(255,255,255,.10)"
                        strokeWidth={1}
                      >
                        {donut.map((entry) => (
                          <Cell
                            key={entry.name}
                            fill={dangerColors[entry.name as DangerLabel]}
                          />
                        ))}
                      </Pie>

                      <text
                        x="50%"
                        y="48%"
                        textAnchor="middle"
                        dominantBaseline="central"
                        fill={donutTotalColor}
                      >
                        <tspan style={{ fontWeight: 950, fontSize: 22 }}>{donutTotal}</tspan>
                      </text>
                      <text
                        x="50%"
                        y="60%"
                        textAnchor="middle"
                        dominantBaseline="central"
                        fill={donutLabelColor}
                      >
                        <tspan style={{ fontSize: 12 }}>submissions</tspan>
                      </text>

                      <RechartsTooltip />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <Stack sx={{ height: "100%", alignItems: "center", justifyContent: "center" }}>
                    <Typography color="text.secondary" variant="body2">
                      No data
                    </Typography>
                  </Stack>
                )}
              </Box>

              <Stack spacing={0.6} sx={{ mt: 1 }}>
                {(DANGER_ORDER as readonly DangerLabel[]).map((label) => {
                  const key = label.toLowerCase() as keyof DangerCounts;
                  const value = (danger[key] ?? 0) as number;

                  return (
                    <Stack
                      key={label}
                      direction="row"
                      sx={{ justifyContent: "space-between", alignItems: "center" }}
>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                        <Box
                          aria-hidden
                          sx={{
                            width: 10,
                            height: 10,
                            borderRadius: 99,
                            backgroundColor: dangerColors[label],
                            border: "1px solid rgba(255,255,255,.18)",
                          }}
                        />
                        <Typography variant="body2" color="text.secondary">
                          {label}
                        </Typography>
                      </Stack>

                      <Typography variant="body2" sx={{ fontWeight: 800 }} >
                        {value}
                      </Typography>
                    </Stack>
                  );
                })}
              </Stack>

              <Divider sx={{ my: 2, opacity: 0.25 }} />

              <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                <Button
                  variant="contained"
                  startIcon={<UploadFileOutlined />}
                  onClick={() => navigate("/submit")}
                  sx={{ borderRadius: 3, textTransform: "none", fontWeight: 950 }}
                >
                  Submit
                </Button>

                {isElevated ? (
                  <Button
                    variant="outlined"
                    startIcon={<ManageSearchOutlined />}
                    onClick={() => navigate("/investigation")}
                    sx={{ borderRadius: 3, textTransform: "none", fontWeight: 900 }}
                  >
                    Open investigation
                  </Button>
                ) : null}
              </Stack>
            </DashboardCard>
          </Grid>

          {/* -------------------------------------------------------------- */}
          {/* -------------------------------------------------------------- */}
          <Grid size={{ xs: 12, md: 5 }}>
            <DashboardCard
              title={isCiso ? "Scope health" : "Your monthly share"}
              icon={<LeaderboardOutlined />}
              className={[
                cardClass
              ].filter(Boolean).join(" ") || undefined}
              right={
                <Chip
                  size="small"
                  label={isCiso ? "Scoped" : "Global"}
                  variant="outlined"
                />
              }
            >
              <Stack spacing={1}>
                <Typography variant="caption" color="text.secondary" sx={{ mt: -0.5 }}>
                  Month-to-date share
                </Typography>

                {isCiso ? (
                  <Typography color="text.secondary">
                    Scope{" "}
                    <Typography component="span" color="text.primary" sx={{ fontWeight: 950 }} >
                      ({scopeLabel ?? "N/A"})
                    </Typography>{" "}
                    ran{" "}
                    <Typography component="span" color="text.primary" sx={{ fontWeight: 950 }} >
                      {scopeCount}
                    </Typography>{" "}
                    of{" "}
                    <Typography component="span" color="text.primary" sx={{ fontWeight: 950 }} >
                      {orgCount}
                    </Typography>{" "}
                    org cases.
                  </Typography>
                ) : (
                  <Typography color="text.secondary">
                    You ran{" "}
                    <Typography component="span" color="text.primary" sx={{ fontWeight: 950 }} >
                      {myCount}
                    </Typography>{" "}
                    of{" "}
                    <Typography component="span" color="text.primary" sx={{ fontWeight: 950 }} >
                      {orgCount}
                    </Typography>{" "}
                    org cases.
                  </Typography>
                )}

                <Box>
                  <Box
                    sx={{
                      height: 8,
                      borderRadius: 99,
                      bgcolor: alpha(theme.palette.divider, 0.4),
                      overflow: "hidden",
                    }}
                  >
                    <Box
                      sx={{
                        width: `${Math.min(100, sharePct)}%`,
                        height: "100%",
                        borderRadius: 99,
                        background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${alpha(
                          theme.palette.primary.main,
                          0.65
                        )})`,
                        transition: "width .6s cubic-bezier(.4,0,.2,1)",
                      }}
                    />
                  </Box>
                  <Stack
                    direction="row"
                    sx={{ justifyContent: "space-between", mt: 0.5 }}
                  >
                    <Typography variant="caption" sx={{ fontWeight: 800 }}>
                      {sharePct}% {isCiso ? "in scope" : "yours"}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {orgCount} org-wide
                    </Typography>
                  </Stack>
                </Box>
              </Stack>

              {showScopeVerdicts ? (
                <>
                  <Divider sx={{ opacity: 0.25, my: 1.5 }} />
                  <Typography variant="caption" color="text.secondary">
                    Scope verdicts this month
                  </Typography>
                  <Stack
                    direction="row"
                    spacing={0.75}
                    sx={{ flexWrap: "wrap", gap: 0.75, mt: 0.75 }}
                  >
                    {(DANGER_ORDER as readonly DangerLabel[]).map((label) => {
                      const key = label.toLowerCase() as keyof DangerCounts;
                      const value = scopeDanger![key] ?? 0;
                      return (
                        <Stack
                          key={label}
                          direction="row"
                          spacing={0.6}
                          sx={{
                            alignItems: "center",
                            px: 1,
                            py: 0.4,
                            borderRadius: 2,
                            border: `1px solid ${alpha(
                              theme.palette.divider,
                              theme.palette.mode === "dark" ? 0.3 : 0.8
                            )}`,
                          }}
                        >
                          <Box
                            aria-hidden
                            sx={{
                              width: 9,
                              height: 9,
                              borderRadius: 99,
                              backgroundColor: dangerColors[label],
                            }}
                          />
                          <Typography variant="caption" color="text.secondary">
                            {label}
                          </Typography>
                          <Typography variant="caption" sx={{ fontWeight: 900 }}>
                            {value}
                          </Typography>
                        </Stack>
                      );
                    })}
                  </Stack>
                </>
              ) : null}

              {home?.spotlight ? (
                <>
                  <Divider sx={{ opacity: 0.25, my: 1.5 }} />

                  <Stack spacing={1}>
                    <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                      <RocketLaunchOutlined fontSize="small" />
                      <Typography sx={{ fontWeight: 900, fontSize: 15 }} >
                        Spotlight
                      </Typography>
                    </Stack>

                    <Typography variant="h6" sx={{ fontWeight: 950, letterSpacing: -0.2 }} >
                      {home.spotlight.title}
                    </Typography>

                    <Typography color="text.secondary" variant="body2">
                      {home.spotlight.description}
                    </Typography>

                    <Box>
                      <Button
                        variant="outlined"
                        onClick={() => navigate(home.spotlight!.cta_path)}
                        sx={{ borderRadius: 3, textTransform: "none", fontWeight: 900 }}
                      >
                        {home.spotlight.cta_label}
                      </Button>
                    </Box>
                  </Stack>
                </>
              ) : null}
            </DashboardCard>
          </Grid>

          {/* -------------------------------------------------------------- */}
          {/* -------------------------------------------------------------- */}
          <Grid size={{ xs: 12 }}>
            <DashboardCard
              title="Recent submissions"
              icon={<HistoryOutlined />}
              className={cardClass}
              right={
                <Button
                  variant="outlined"
                  onClick={() => navigate("/submissions")}
                  sx={{ borderRadius: 3, textTransform: "none", fontWeight: 900 }}
                >
                  See more
                </Button>
              }
            >
              <Box sx={{ px: { xs: 1.5, md: 2 }, pb: 1.5, mt: -0.5 }}>
                <Typography variant="body2" color="text.secondary">
                  Your last 3 items (most recent first)
                </Typography>
              </Box>

              {recentQuery.isLoading ? (
                <Box sx={{ px: { xs: 1.5, md: 2 }, pb: 2 }}>
                  <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                    <CircularProgress
                      size={18}
                      sx={capabilities.effects.hasAlertStates
                        ? { animation: "codecStatic 2s ease-in-out infinite, CircularProgress-keyframes-circular-rotate 1.4s linear infinite" }
                        : undefined}
                    />
                    <Typography color="text.secondary" variant="body2">
                      {capabilities.effects.hasPortalEffect
                        ? "// SCANNING TEMPORAL RECORDS…"
                        : capabilities.effects.hasStealthMode
                        ? "ACCESSING MISSION ARCHIVE…"
                        : capabilities.effects.hasNeonEffect
                        ? "QUERYING THREAT_MATRIX…"
                        : "Loading submissions…"}
                    </Typography>
                  </Stack>
                </Box>
              ) : recentQuery.isError ? (
                <Box sx={{ px: { xs: 1.5, md: 2 }, pb: 2 }}>
                  <Alert severity="error">Recent submissions unavailable.</Alert>
                </Box>
              ) : recent.length === 0 ? (
                capabilities.effects.hasStealthMode ? (
                  <Box
                    className="cardboard-box"
                    sx={{
                      mx: { xs: 1.5, md: 2 },
                      mb: 2,
                      px: 2,
                      py: 1.5,
                      borderRadius: "4px",
                      fontFamily: '"IBM Plex Mono", monospace',
                      fontSize: 11,
                      fontWeight: 900,
                      letterSpacing: "0.1em",
                    }}
                  >
                  </Box>
                ) : (
                  <Box sx={{ px: { xs: 1.5, md: 2 }, pb: 2 }}>
                    <Alert severity="info">
                      {capabilities.effects.hasPortalEffect
                        ? "// NO TEMPORAL RECORDS FOUND — submit your first case to begin the timeline."
                        : "No submissions yet."}
                    </Alert>
                  </Box>
                )
              ) : (
                <Box sx={{ overflowX: "auto" }}>
                  <Table sx={{ minWidth: 920 }}>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 950 }}>ID</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Status</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Artifact</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Date</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Type</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Result</TableCell>
                      </TableRow>
                    </TableHead>

                    <TableBody>
                      {recent.map((r) => (
                        <TableRow key={String(r.id)} hover>
                          <TableCell>
                            <Stack direction="row" spacing={1} sx={{ alignItems: "center" }} >
                              <Button
                                size="small"
                                variant="contained"
                                component={RouterLink}
                                to={`/submissions?q=${encodeURIComponent(
                                  String(r.id)
                                )}&open=${encodeURIComponent(String(r.id))}`}
                                sx={{
                                  borderRadius: 3,
                                  textTransform: "none",
                                  fontWeight: 950,
                                }}
                              >
                                {r.id}
                              </Button>

                              <Tooltip title="Open in Submissions">
                                <IconButton
                                  size="small"
                                  component={RouterLink}
                                  to={`/submissions?q=${encodeURIComponent(
                                    String(r.id)
                                  )}&open=${encodeURIComponent(String(r.id))}`}
                                >
                                  <OpenInNewOutlined fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            </Stack>
                          </TableCell>

                          <TableCell>
                            <StatusChip status={r.status as any} minWidth={BADGE_W} />
                          </TableCell>

                          <TableCell title={r.artifact ?? ""}>
                            <Typography
                              sx={{
                                maxWidth: 360,
                                whiteSpace: "nowrap",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                              }}
                            >
                              {short(r.artifact, 64) || "—"}
                            </Typography>
                          </TableCell>

                          <TableCell>{fmtDate(r.created_at)}</TableCell>

                          <TableCell>
                            <Chip
                              label={(r.type ?? "—").toString().toUpperCase()}
                              size="small"
                              variant="outlined"
                              sx={{
                                fontWeight: 900,
                                minWidth: BADGE_W,
                                justifyContent: "center",
                                "& .MuiChip-label": { width: "100%", textAlign: "center" },
                              }}
                            />
                          </TableCell>

                          <TableCell>
                            <ResultChip result={r.result as any} minWidth={BADGE_W} />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Box>
              )}
            </DashboardCard>
          </Grid>
        </Grid>

        {/* ---------------------------------------------------------------- */}
        {/* ---------------------------------------------------------------- */}
        <Dialog open={showScopeModal} maxWidth="sm" fullWidth>
          <DialogTitle>Select your management scope</DialogTitle>
          <DialogContent>
            <Stack spacing={1.25} sx={{ mt: 1 }}>
              <Typography color="text.secondary">
                This controls dashboards and submission visibility for your CISO view.
              </Typography>

              <Card
                sx={{
                  borderRadius: 3,
                  border: `1px solid ${alpha(theme.palette.divider, theme.palette.mode === "dark" ? 0.18 : 0.7)}`,
                  background:
                    theme.palette.mode === "dark"
                      ? "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))"
                      : `linear-gradient(180deg, ${alpha("#fff", 0.88)}, ${alpha(theme.palette.grey[50], 0.96)})`,
                }}
              >
                <CardContent>
                  <Stack spacing={1}>
                    <Typography sx={{ fontWeight: 900 }} >Suggested scopes</Typography>

                    <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                      {suggested.region ? (
                        <Chip
                          icon={<PublicOutlined />}
                          label={`Region: ${suggested.region}`}
                          clickable
                          onClick={() => setScopeChoice(suggested.region ?? "")}
                          variant={scopeChoice === suggested.region ? "filled" : "outlined"}
                        />
                      ) : null}

                      {suggested.country ? (
                        <Chip
                          icon={<ApartmentOutlined />}
                          label={`Country: ${suggested.country}`}
                          clickable
                          onClick={() => setScopeChoice(suggested.country ?? "")}
                          variant={scopeChoice === suggested.country ? "filled" : "outlined"}
                        />
                      ) : null}

                      {suggested.gbu ? (
                        <Chip
                          label={`GBU: ${suggested.gbu}`}
                          clickable
                          onClick={() => setScopeChoice(suggested.gbu ?? "")}
                          variant={scopeChoice === suggested.gbu ? "filled" : "outlined"}
                        />
                      ) : null}

                      {!suggested.region && !suggested.country && !suggested.gbu ? (
                        <Chip label="No suggestions" variant="outlined" />
                      ) : null}
                    </Stack>

                    <Typography variant="caption" color="text.secondary">
                      You can change it later if your responsibilities change.
                    </Typography>

                    {scopeMutation.isError ? (
                      <Alert severity="error">Failed to set scope.</Alert>
                    ) : null}
                  </Stack>
                </CardContent>
              </Card>
            </Stack>
          </DialogContent>

          <DialogActions>
            <Button
              variant="contained"
              disabled={!scopeChoice || scopeMutation.isPending}
              onClick={() => scopeMutation.mutate({ scope: scopeChoice })}
              sx={{ borderRadius: 3, textTransform: "none", fontWeight: 950 }}
            >
              {scopeMutation.isPending ? "Saving…" : "Confirm scope"}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Box>
  );
}