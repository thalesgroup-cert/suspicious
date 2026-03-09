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
    dangerous: 0
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
  const effectiveScope = isCiso ? scope : "ALL";

  const summaryQuery = useQuery<DashboardSummary>({
    queryKey: ["dashboardSummary", month, year, effectiveScope],
    queryFn: async () => {
      return getDashboardSummary({ month, year, scope: effectiveScope });
    },
    retry: false,
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
      queryKey: ["dashboardSummary", hm, hy, effectiveScope, "history"],
      queryFn: async () => {
        return getDashboardSummary({ month: hm, year: hy, scope: effectiveScope });
      },
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
            </Box>

            <Box sx={{ display: "grid", gap: 2 }}>
              <ThreatDistributionPanel dangerCounts={data.danger_counts} />
            </Box>
          </Box>
        </Box>
      </Container>
    </Box>
  );
}
