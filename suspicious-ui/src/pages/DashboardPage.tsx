// file: src/pages/DashboardPage.tsx
import * as React from "react";
import { Alert, Box, Button, Container, Stack } from "@mui/material";
import { TrendingUpOutlined } from "@mui/icons-material";
import { useQueries, useQuery } from "@tanstack/react-query";

import { getMe } from "@/api/auth";
import { getDashboardSummary, type DashboardSummary } from "@/features/dashboard/api";

import OverviewHeader from "@/features/dashboard/components/OverviewHeader";
import ThreatDistributionPanel from "@/features/dashboard/components/ThreatDistributionPanel";
import TopPrefixesPanel from "@/features/dashboard/components/TopPrefixesPanel";
import RankedPrefixesTable from "@/features/dashboard/components/RankedPrefixesTable";
import { DashboardEmpty, DashboardLoading } from "@/features/dashboard/components/StatePanels";
import KpiTrendPanels from "@/features/dashboard/components/KpiTrendPanels";

function monthName(m: number) {
  return new Date(2000, m - 1, 1).toLocaleString("en", { month: "long" });
}
function monthNameShort(m: number) {
  return new Date(2000, m - 1, 1).toLocaleString("en", { month: "short" });
}
function clampTopN<T>(arr: T[], n: number) {
  return arr.length > n ? arr.slice(0, n) : arr;
}

function getMonthWindow(month: number, year: number, windowSize: number) {
  // oldest -> newest, includes current
  const out: Array<{ month: number; year: number }> = [];
  let m = month;
  let y = year;
  for (let i = 0; i < windowSize; i++) {
    out.push({ month: m, year: y });
    m -= 1;
    if (m <= 0) {
      m = 12;
      y -= 1;
    }
  }
  return out.reverse();
}

function makeMockDashboard(month: number, year: number, scope: string): DashboardSummary {
  return {
    month,
    year,
    scope,
    kpis: { new_users: 42, total_reporters: 1840, total_cases: 612 },
    danger_counts: {
      failure: 4,
      safe: 210,
      inconclusive: 78,
      suspicious: 185,
      dangerous: 92,
      malicious: 43,
    },
    top_prefixes: [
      { label: "paypal", value: 64 },
      { label: "microsoft", value: 58 },
      { label: "docusign", value: 51 },
      { label: "google", value: 45 },
      { label: "amazon", value: 39 },
      { label: "fedex", value: 36 },
      { label: "security", value: 31 },
      { label: "invoice", value: 29 },
      { label: "hr", value: 22 },
      { label: "it-support", value: 18 },
    ],
  };
}

const EMPTY_SUMMARY: DashboardSummary = {
  month: 1,
  year: 1970,
  scope: "ALL",
  kpis: { new_users: 0, total_reporters: 0, total_cases: 0 },
  danger_counts: {
    failure: 0,
    safe: 0,
    inconclusive: 0,
    suspicious: 0,
    dangerous: 0,
    malicious: 0,
  },
  top_prefixes: [],
};

export default function DashboardPage() {
  const now = new Date();

  const [openKpiTrends, setOpenKpiTrends] = React.useState(false);
  const [selectedMetric, setSelectedMetric] = React.useState<string | undefined>(undefined);

  const [month, setMonth] = React.useState(now.getMonth() + 1);
  const [year, setYear] = React.useState(now.getFullYear());
  const [scope, setScope] = React.useState<string>("ALL");
  const [prefixSearch, setPrefixSearch] = React.useState("");

  const [trendWindow, setTrendWindow] = React.useState<number>(6);

  const meQuery = useQuery({ queryKey: ["me"], queryFn: getMe, retry: false });

  const groups: string[] = (meQuery.data as any)?.groups ?? [];
  const isCiso = groups.includes("CISO");
  const isElevated = groups.includes("CISO") || groups.includes("CERT");
  const cisoScope: string | undefined = (meQuery.data as any)?.ciso_scope;

  const useMockDashboard = import.meta.env.VITE_USE_MOCK_DASHBOARD === "true";
  const effectiveScope = isCiso ? scope : "ALL";

  const summaryQuery = useQuery<DashboardSummary>({
    queryKey: ["dashboardSummary", month, year, effectiveScope, useMockDashboard],
    queryFn: async () => {
      if (useMockDashboard) {
        await new Promise((r) => setTimeout(r, 250));
        return makeMockDashboard(month, year, effectiveScope);
      }
      return getDashboardSummary({ month, year, scope: effectiveScope });
    },
    enabled: useMockDashboard ? true : !!meQuery.data,
    retry: false,
    initialData: () =>
      useMockDashboard
        ? makeMockDashboard(month, year, effectiveScope)
        : {
            month,
            year,
            scope: effectiveScope,
            kpis: { new_users: 0, total_reporters: 0, total_cases: 0 },
            danger_counts: {
              failure: 0,
              safe: 0,
              inconclusive: 0,
              suspicious: 0,
              dangerous: 0,
              malicious: 0,
            },
            top_prefixes: [],
          },
  });

  // IMPORTANT: hooks must be above conditional returns.
  const data: DashboardSummary = summaryQuery.data ?? {
    ...EMPTY_SUMMARY,
    month,
    year,
    scope: effectiveScope,
  };

  const historyParams = React.useMemo(
    () => getMonthWindow(month, year, Math.max(1, trendWindow)),
    [month, year, trendWindow]
  );

  const historyQueries = useQueries({
    queries: historyParams.map(({ month: hm, year: hy }) => ({
      queryKey: ["dashboardSummary", hm, hy, effectiveScope, useMockDashboard, "history"],
      queryFn: async () => {
        if (useMockDashboard) {
          await new Promise((r) => setTimeout(r, 60));
          const mod = (hm + hy) % 20;
          return {
            month: hm,
            year: hy,
            scope: effectiveScope,
            kpis: {
              new_users: 20 + mod,
              total_reporters: 1000 + mod * 10,
              total_cases: 300 + mod * 5,
            },
            danger_counts: { failure: 0, safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0, malicious: 0 },
            top_prefixes: [],
          } as DashboardSummary;
        }
        return getDashboardSummary({ month: hm, year: hy, scope: effectiveScope });
      },
      enabled: useMockDashboard ? true : !!meQuery.data,
      retry: false,
      staleTime: 30_000,
    })),
  });

  const top10 = React.useMemo(() => clampTopN(data.top_prefixes ?? [], 10), [data.top_prefixes]);

  const filteredTop = React.useMemo(() => {
    if (!prefixSearch) return top10;
    const q = prefixSearch.toLowerCase();
    return top10.filter((x) => x.label.toLowerCase().includes(q));
  }, [top10, prefixSearch]);

  const pageSubtitle = React.useMemo(() => {
    return `${monthName(data.month)} ${data.year}${isCiso ? ` • Scope: ${data.scope}` : ""}`;
  }, [data.month, data.year, data.scope, isCiso]);

  const kpiSpark = React.useMemo(() => {
    const labels = historyParams.map((p) => `${monthNameShort(p.month)} ${String(p.year).slice(-2)}`);

    const toNumOrNull = (v: unknown) => (typeof v === "number" ? v : null);
    const series = historyQueries.map((q) => q.data?.kpis);

    return {
      labels,
      newUsers: series.map((k) => toNumOrNull(k?.new_users)),
      reporters: series.map((k) => toNumOrNull(k?.total_reporters)),
      submissions: series.map((k) => toNumOrNull(k?.total_cases)),
    };
  }, [historyParams, historyQueries]);

  const isEmpty = React.useMemo(() => {
    const k = data.kpis;
    const noKpis =
      (k?.new_users ?? 0) === 0 && (k?.total_reporters ?? 0) === 0 && (k?.total_cases ?? 0) === 0;
    const noPrefixes = (data.top_prefixes?.length ?? 0) === 0;
    const counts = Object.values(data.danger_counts ?? {});
    const noCounts = counts.length === 0 || counts.every((v) => (v ?? 0) === 0);
    return noKpis && noPrefixes && noCounts;
  }, [data.kpis, data.top_prefixes, data.danger_counts]);

  const isInitialLoading = meQuery.isLoading || summaryQuery.isLoading;

  const openTrends = React.useCallback((metric?: string) => {
    setSelectedMetric(metric);
    setOpenKpiTrends(true);
  }, []);

  if (isInitialLoading) return <DashboardLoading />;

  if (summaryQuery.isError) {
    return (
      <Container maxWidth="xl" sx={{ py: 3 }}>
        <Alert
          severity="error"
          action={
            <Box
              component="span"
              sx={{ cursor: "pointer", textDecoration: "underline" }}
              onClick={() => summaryQuery.refetch()}
            >
              Retry
            </Box>
          }
        >
          Dashboard data unavailable.
        </Alert>
      </Container>
    );
  }

  return (
    <Box sx={{ minHeight: "100vh" }}>
      <OverviewHeader
        title="Dashboard"
        subtitle={pageSubtitle}
        isElevated={isElevated}
        isCiso={isCiso}
        month={month}
        year={year}
        scope={scope}
        cisoScope={cisoScope}
        onMonthChange={setMonth}
        onYearChange={setYear}
        onScopeChange={setScope}
        onRefresh={() => summaryQuery.refetch()}
        refreshing={summaryQuery.isFetching}
        trendWindow={trendWindow}
        onTrendWindowChange={setTrendWindow}
      />

      <Container maxWidth="xl" sx={{ py: 2.5 }}>
        {isEmpty ? (
          <DashboardEmpty
            title="No signals for this period"
            description="Try a different month/year (or scope if available)."
            onRefresh={() => summaryQuery.refetch()}
            canAdjust={isElevated}
          />
        ) : null}

        <Box sx={{ opacity: isEmpty ? 0.5 : 1, pointerEvents: isEmpty ? "none" : "auto" }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
            <Box>
              <Box sx={{ fontWeight: 900, fontSize: 14 }}>Overview</Box>
              <Box sx={{ color: "text.secondary", fontSize: 12 }}>
                KPI evolution for {monthName(data.month)} {data.year}
              </Box>
            </Box>
          </Stack>

          {/* ✅ 3 chart panels (GlassCard + ComposedChart), each panel opens drawer */}
          <KpiTrendPanels
            spark={kpiSpark}
            trendWindow={trendWindow}
            onOpenTrends={(metric) => openTrends(metric)}
          />

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", md: "2fr 1fr" },
              gap: 2,
              mt: 2,
              alignItems: "start",
            }}
          >
            <Box sx={{ display: "grid", gap: 2 }}>
              <TopPrefixesPanel data={filteredTop} />
              <RankedPrefixesTable data={filteredTop} search={prefixSearch} onSearchChange={setPrefixSearch} />
            </Box>

            <Box sx={{ display: "grid", gap: 2 }}>
              <ThreatDistributionPanel dangerCounts={data.danger_counts} />

              <Box
                sx={{
                  borderRadius: 3,
                  border: "1px solid",
                  borderColor: "divider",
                  bgcolor: "background.paper",
                  p: 2,
                }}
              >
                <Box sx={{ fontWeight: 900, fontSize: 14, mb: 0.5 }}>Quick actions</Box>
                <Box sx={{ color: "text.secondary", fontSize: 12, mb: 1.5 }}>
                  Actions depend on routes/endpoints. These are placeholders.
                </Box>

                <Box sx={{ display: "grid", gap: 1 }}>
                  <Box
                    component="button"
                    disabled
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "10px 12px",
                      borderRadius: 12,
                      border: "1px solid rgba(255,255,255,0.12)",
                      background: "transparent",
                      color: "inherit",
                      cursor: "not-allowed",
                      opacity: 0.7,
                      font: "inherit",
                    }}
                  >
                    View cases (TODO)
                  </Box>
                  <Box
                    component="button"
                    disabled
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "10px 12px",
                      borderRadius: 12,
                      border: "1px solid rgba(255,255,255,0.12)",
                      background: "transparent",
                      color: "inherit",
                      cursor: "not-allowed",
                      opacity: 0.7,
                      font: "inherit",
                    }}
                  >
                    Export report (TODO)
                  </Box>
                </Box>
              </Box>
            </Box>
          </Box>
        </Box>
      </Container>
    </Box>
  );
}
