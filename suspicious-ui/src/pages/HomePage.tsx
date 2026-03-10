// src/pages/HomePage.tsx
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
import {
  ApartmentOutlined,
  ManageSearchOutlined,
  OpenInNewOutlined,
  PublicOutlined,
  RocketLaunchOutlined,
  ShieldOutlined,
  UploadFileOutlined,
  DonutLargeOutlined,
  HistoryOutlined,
} from "@mui/icons-material";
import { useNavigate, Link as RouterLink } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useTheme } from "@mui/material/styles";
import { api } from "@/api/client";
import { getMe, type Me } from "@/api/auth";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
} from "recharts";

import { StatusChip } from "@/shared/components/StatusChip";
import { ResultChip } from "@/shared/components/ResultChip";

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

type SubmissionRow = {
  id: number | string;
  status?: string;
  info?: string;
  created_at?: string;
  tests_done?: number;
  type?: string;
  result?: string;
};

type SubmissionsResponse = {
  results?: SubmissionRow[];
  count?: number;
};

async function getMyRecentSubmissions(): Promise<SubmissionRow[]> {
  const res = await api.get("/submissions/", {
    params: { mine: 1, page_size: 3, ordering: "-created_at" },
  });

  const data = res.data as SubmissionsResponse | SubmissionRow[];
  if (Array.isArray(data)) return data.slice(0, 3);
  return (data.results ?? []).slice(0, 3);
}

function short(text: string | undefined, max = 64) {
  const t = (text ?? "").trim();
  if (!t) return "";
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function fmtDate(iso: string | undefined) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

function sum(values: number[]) {
  return values.reduce((a, b) => a + b, 0);
}
function DashboardCard(
  props: React.PropsWithChildren<{
    title: string;
    icon?: React.ReactNode;
    right?: React.ReactNode;
    sx?: Record<string, unknown>;
    contentSx?: Record<string, unknown>;
  }>
) {
  const { title, icon, right, sx, contentSx, children } = props;

  return (
    <Card
      sx={{
        height: "100%",
        borderRadius: 3,
        border: "1px solid rgba(255,255,255,.10)",
        background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
        ...sx,
      }}
    >
      <CardContent
        sx={{
          p: { xs: 1.5, md: 2 },
          ...contentSx,
        }}
      >
        <Stack
          direction="row"
          alignItems="center"
          justifyContent="space-between"
          sx={{ mb: 1 }}
        >
          <Stack direction="row" spacing={0.9} alignItems="center">
            {icon ? (
              <Box
                sx={{
                  width: 34,
                  height: 34,
                  borderRadius: 2,
                  display: "grid",
                  placeItems: "center",
                  border: "1px solid rgba(255,255,255,.12)",
                  background:
                    "linear-gradient(135deg, rgba(56,189,248,.14), rgba(120,119,198,.12))",
                  "& svg": { fontSize: 18 },
                }}
              >
                {icon}
              </Box>
            ) : null}

            <Typography fontWeight={900} fontSize={15}>
              {title}
            </Typography>
          </Stack>

          {right}
        </Stack>

        <Divider sx={{ opacity: 0.25, mb: 1.5 }} />
        {children}
      </CardContent>
    </Card>
  );
}

function SectionTitle(props: { title: string; right?: React.ReactNode }) {
  return (
    <Stack
      direction="row"
      alignItems="center"
      justifyContent="space-between"
      sx={{ mb: 1 }}
    >
      <Typography fontWeight={950} letterSpacing={-0.2}>
        {props.title}
      </Typography>
      {props.right}
    </Stack>
  );
}

const DANGER_ORDER = ["Safe", "Inconclusive", "Suspicious", "Dangerous"] as const;
type DangerLabel = (typeof DANGER_ORDER)[number];

const DANGER_COLORS: Record<DangerLabel, string> = {
  Safe: "#22C55E",
  Inconclusive: "#A3A3A3",
  Suspicious: "#F59E0B",
  Dangerous: "#EF4444",
};

export default function HomePage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const BADGE_W = 132;
  const TOP_OFFSET = 50;

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
    .map((name) => {
      const key = name.toLowerCase() as keyof DangerCounts;
      const value = (danger[key] ?? 0) as number;
      return { name, value };
    })
    .filter((d) => d.value > 0);

  const donutTotal = sum(donut.map((d) => d.value));
  const donutTotalColor = theme.palette.text.primary;
  const donutLabelColor = theme.palette.text.secondary;

  const recent = recentQuery.data ?? [];

  return (
    <Box
      sx={{
        px: { xs: 2, md: 3 },
        pb: 8,
        pt: 0,
      }}
    >
      <Box sx={{ maxWidth: 1280, mx: "auto" }}>
        <Stack
          direction={{ xs: "column", md: "row" }}
          spacing={1.5}
          sx={{ mb: 2 }}
          justifyContent="space-between"
        >
          <Stack direction="row" spacing={1.5} alignItems="flex-start" sx={{ minWidth: 0 }}>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="h5" fontWeight={980} letterSpacing={-0.6} noWrap>
                Welcome, {displayName}
              </Typography>
            </Box>
          </Stack>
        </Stack>

        {homeQuery.isError ? (
          <Box sx={{ mb: 2 }}>
            <Alert severity="error">Home summary unavailable.</Alert>
          </Box>
        ) : null}

        <Grid container spacing={2}>
          <Grid item xs={12} md={7}>
            <DashboardCard
              title="Threat distribution"
              icon={<DonutLargeOutlined />}
              right={<Chip size="small" label="Monthly" variant="outlined" />}
            >
              <Box sx={{ height: 220 }}>
                {homeQuery.isLoading ? (
                  <Stack sx={{ height: "100%" }} alignItems="center" justifyContent="center">
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
                          <Cell key={entry.name} fill={DANGER_COLORS[entry.name as DangerLabel]} />
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
                  <Stack sx={{ height: "100%" }} alignItems="center" justifyContent="center">
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
                      justifyContent="space-between"
                      alignItems="center"
                    >
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Box
                          aria-hidden
                          sx={{
                            width: 10,
                            height: 10,
                            borderRadius: 99,
                            backgroundColor: DANGER_COLORS[label],
                            border: "1px solid rgba(255,255,255,.18)",
                          }}
                        />
                        <Typography variant="body2" color="text.secondary">
                          {label}
                        </Typography>
                      </Stack>

                      <Typography variant="body2" fontWeight={800}>
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

          <Grid item xs={12} md={5}>
            <DashboardCard
              title="Snapshot"
              icon={<ShieldOutlined />}
              right={
                <Chip
                  size="small"
                  label={isCiso ? "Scoped" : "Global"}
                  variant="outlined"
                />
              }
            >
              <Stack spacing={0.75}>
                <Typography variant="caption" color="text.secondary" sx={{ mt: -0.5 }}>
                  Month-to-date volume
                </Typography>

                {isCiso ? (
                  <Typography color="text.secondary">
                    Scope{" "}
                    <Typography component="span" fontWeight={950} color="text.primary">
                      ({scopeLabel ?? "N/A"})
                    </Typography>{" "}
                    published{" "}
                    <Typography component="span" fontWeight={950} color="text.primary">
                      {scopeCount}
                    </Typography>{" "}
                    items.
                  </Typography>
                ) : (
                  <Typography color="text.secondary">
                    Everyone published{" "}
                    <Typography component="span" fontWeight={950} color="text.primary">
                      {everyoneCount}
                    </Typography>{" "}
                    items.
                  </Typography>
                )}
              </Stack>

              {home?.spotlight ? (
                <>
                  <Divider sx={{ opacity: 0.25, my: 1.5 }} />

                  <Stack spacing={1}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <RocketLaunchOutlined fontSize="small" />
                      <Typography fontWeight={900} fontSize={15}>
                        Spotlight
                      </Typography>
                    </Stack>

                    <Typography variant="h6" fontWeight={950} letterSpacing={-0.2}>
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

          <Grid item xs={12}>
            <DashboardCard
              title="Recent submissions"
              icon={<HistoryOutlined />}
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
                  <Stack direction="row" spacing={1} alignItems="center">
                    <CircularProgress size={18} />
                    <Typography color="text.secondary" variant="body2">
                      Loading submissions…
                    </Typography>
                  </Stack>
                </Box>
              ) : recentQuery.isError ? (
                <Box sx={{ px: { xs: 1.5, md: 2 }, pb: 2 }}>
                  <Alert severity="error">Recent submissions unavailable.</Alert>
                </Box>
              ) : recent.length === 0 ? (
                <Box sx={{ px: { xs: 1.5, md: 2 }, pb: 2 }}>
                  <Alert severity="info">No submissions yet.</Alert>
                </Box>
              ) : (
                <Box sx={{ overflowX: "auto" }}>
                  <Table sx={{ minWidth: 920 }}>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 950 }}>ID</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Status</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Info</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Date</TableCell>
                        <TableCell sx={{ fontWeight: 950, textAlign: "right" }}>Tests</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Type</TableCell>
                        <TableCell sx={{ fontWeight: 950 }}>Result</TableCell>
                      </TableRow>
                    </TableHead>

                    <TableBody>
                      {recent.map((r) => (
                        <TableRow key={String(r.id)} hover>
                          <TableCell>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <Button
                                size="small"
                                variant="contained"
                                component={RouterLink}
                                to={`/submissions?q=${encodeURIComponent(
                                  String(r.id)
                                )}&open=${encodeURIComponent(String(r.id))}`}
                                sx={{ borderRadius: 3, textTransform: "none", fontWeight: 950 }}
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

                          <TableCell title={r.info ?? ""}>
                            <Typography
                              sx={{
                                maxWidth: 360,
                                whiteSpace: "nowrap",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                              }}
                            >
                              {short(r.info, 64) || "—"}
                            </Typography>
                          </TableCell>

                          <TableCell>{fmtDate(r.created_at)}</TableCell>

                          <TableCell sx={{ textAlign: "right", fontWeight: 900 }}>
                            {typeof r.tests_done === "number" ? r.tests_done : "—"}
                          </TableCell>

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
                  border: "1px solid rgba(255,255,255,.10)",
                  background: "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
                }}
              >
                <CardContent>
                  <Stack spacing={1}>
                    <Typography fontWeight={900}>Suggested scopes</Typography>

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