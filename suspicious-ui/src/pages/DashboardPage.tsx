import * as React from "react";
import { Alert, Box, Container, Stack } from "@mui/material";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Responsive, WidthProvider, type Layout } from "react-grid-layout/legacy";

import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";

import { getMe } from "@/api/auth";
import { getDashboardSummary, type DashboardSummary } from "@/features/dashboard/api";

import OverviewHeader from "@/features/dashboard/components/OverviewHeader";
import ThreatDistributionPanel from "@/features/dashboard/components/ThreatDistributionPanel";
import TopPrefixesPanel from "@/features/dashboard/components/TopPrefixesPanel";
import { DashboardEmpty, DashboardLoading } from "@/features/dashboard/components/StatePanels";
import KpiTrendPanels from "@/features/dashboard/components/KpiTrendPanels";

function monthName(m: number) {
  return new Date(2000, m - 1, 1).toLocaleString("en", { month: "long" });
}

function monthNameShort(m: number) {
  return new Date(2000, m - 1, 1).toLocaleString("en", { month: "short" });
}

function getMonthWindow(month: number, year: number, windowSize: number) {
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
    dangerous: 0,
    malicious: 0,
  },
  top_prefixes: [],
};

const DASHBOARD_PANEL_KEYS = {
  KPI_TRENDS: "kpi-trends",
  TOP_PREFIXES: "top-prefixes",
  THREAT_DISTRIBUTION: "threat-distribution",
} as const;

const DASHBOARD_BREAKPOINTS = {
  lg: 1200,
  md: 900,
  sm: 600,
  xs: 0,
};

const DASHBOARD_COLS = {
  lg: 12,
  md: 12,
  sm: 6,
  xs: 1,
};

type ResponsiveLayouts = Partial<Record<string, Layout>>;

const DEFAULT_DASHBOARD_LAYOUTS: ResponsiveLayouts = {
  lg: [
    { i: DASHBOARD_PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: 12, h: 6, minW: 6, minH: 4 },
    { i: DASHBOARD_PANEL_KEYS.TOP_PREFIXES, x: 0, y: 6, w: 8, h: 10, minW: 4, minH: 6 },
    { i: DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION, x: 8, y: 6, w: 4, h: 10, minW: 4, minH: 6 },
  ],
  md: [
    { i: DASHBOARD_PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: 12, h: 6, minW: 6, minH: 4 },
    { i: DASHBOARD_PANEL_KEYS.TOP_PREFIXES, x: 0, y: 6, w: 7, h: 10, minW: 4, minH: 6 },
    { i: DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION, x: 7, y: 6, w: 5, h: 10, minW: 4, minH: 6 },
  ],
  sm: [
    { i: DASHBOARD_PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: 6, h: 6, minH: 4 },
    { i: DASHBOARD_PANEL_KEYS.TOP_PREFIXES, x: 0, y: 6, w: 6, h: 10, minH: 6 },
    { i: DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION, x: 0, y: 16, w: 6, h: 10, minH: 6 },
  ],
  xs: [
    { i: DASHBOARD_PANEL_KEYS.KPI_TRENDS, x: 0, y: 0, w: 1, h: 6, minH: 4 },
    { i: DASHBOARD_PANEL_KEYS.TOP_PREFIXES, x: 0, y: 6, w: 1, h: 10, minH: 6 },
    { i: DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION, x: 0, y: 16, w: 1, h: 10, minH: 6 },
  ],
};

const ResponsiveGridLayout = WidthProvider(Responsive);

function isValidLayouts(value: unknown): value is ResponsiveLayouts {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function getStorageKey(userId?: string | number) {
  return `dashboard:layouts:${userId ?? "anonymous"}`;
}

function loadLayoutsFromStorage(storageKey: string): ResponsiveLayouts {
  if (typeof window === "undefined") return DEFAULT_DASHBOARD_LAYOUTS;

  try {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) return DEFAULT_DASHBOARD_LAYOUTS;

    const parsed = JSON.parse(raw);
    return isValidLayouts(parsed) ? parsed : DEFAULT_DASHBOARD_LAYOUTS;
  } catch {
    return DEFAULT_DASHBOARD_LAYOUTS;
  }
}

function saveLayoutsToStorage(storageKey: string, layouts: ResponsiveLayouts) {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.setItem(storageKey, JSON.stringify(layouts));
  } catch {
    // ignore storage failures
  }
}

type DashboardPanelShellProps = {
  title: string;
  children: React.ReactNode;
};

const DashboardPanelShell = React.memo(function DashboardPanelShell({
  title,
  children,
}: DashboardPanelShellProps) {
  return (
    <Box
      sx={{
        height: "100%",
        minHeight: 0,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      <Box
        className="dashboard-panel-drag-handle"
        sx={{
          flexShrink: 0,
          mb: 1,
          px: 0.5,
          fontSize: 12,
          fontWeight: 700,
          color: "text.secondary",
          cursor: "move",
          userSelect: "none",
        }}
      >
        {title}
      </Box>

      <Box
        sx={{
          flex: 1,
          minHeight: 0,
          overflow: "hidden",
        }}
      >
        {children}
      </Box>
    </Box>
  );
});

export default function DashboardPage() {
  const now = new Date();

  const [openKpiTrends, setOpenKpiTrends] = React.useState(false);
  const [selectedMetric, setSelectedMetric] = React.useState<string | undefined>(undefined);

  const [month, setMonth] = React.useState(now.getMonth() + 1);
  const [year, setYear] = React.useState(now.getFullYear());
  const [scope, setScope] = React.useState<string>("ALL");
  const [trendWindow, setTrendWindow] = React.useState<number>(6);

  const meQuery = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  const groups: string[] = (meQuery.data as any)?.groups ?? [];
  const isCiso = groups.includes("CISO");
  const isElevated = groups.includes("CISO") || groups.includes("CERT");
  const cisoScope: string | undefined = (meQuery.data as any)?.ciso_scope;
  const effectiveScope = isCiso ? scope : "ALL";
  const userId = (meQuery.data as any)?.id;

  const storageKey = React.useMemo(() => getStorageKey(userId), [userId]);

  const [layouts, setLayouts] = React.useState<ResponsiveLayouts>(() =>
    loadLayoutsFromStorage(storageKey)
  );

  React.useEffect(() => {
    setLayouts(loadLayoutsFromStorage(storageKey));
  }, [storageKey]);

  const summaryQuery = useQuery<DashboardSummary>({
    queryKey: ["dashboardSummary", month, year, effectiveScope],
    queryFn: async () => {
      return getDashboardSummary({ month, year, scope: effectiveScope });
    },
    retry: false,
  });

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
      (k?.new_users ?? 0) === 0 &&
      (k?.total_reporters ?? 0) === 0 &&
      (k?.total_cases ?? 0) === 0;
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

  const handleLayoutsChange = React.useCallback(
    (_currentLayout: Layout, allLayouts: Partial<Record<string, Layout>>) => {
      const nextLayouts: ResponsiveLayouts = allLayouts;
      setLayouts(nextLayouts);
      saveLayoutsToStorage(storageKey, nextLayouts);
    },
    [storageKey]
  );

  const resetLayouts = React.useCallback(() => {
    setLayouts(DEFAULT_DASHBOARD_LAYOUTS);
    saveLayoutsToStorage(storageKey, DEFAULT_DASHBOARD_LAYOUTS);
  }, [storageKey]);

  const strMonth = String(month).padStart(2, "0");
  const strYear = String(year);

  void openKpiTrends;
  void selectedMetric;

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
    <Box>
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

            <Box
              component="button"
              type="button"
              onClick={resetLayouts}
              sx={{
                border: 0,
                background: "transparent",
                color: "text.secondary",
                fontSize: 12,
                fontWeight: 700,
                cursor: "pointer",
                textDecoration: "underline",
              }}
            >
              Reset layout
            </Box>
          </Stack>

          <ResponsiveGridLayout
            className="dashboard-layout"
            layouts={layouts}
            breakpoints={DASHBOARD_BREAKPOINTS}
            cols={DASHBOARD_COLS}
            rowHeight={28}
            margin={[16, 16]}
            containerPadding={[0, 0]}
            compactType="vertical"
            preventCollision={false}
            isDraggable
            isResizable
            useCSSTransforms
            measureBeforeMount={false}
            draggableHandle=".dashboard-panel-drag-handle"
            onLayoutChange={handleLayoutsChange}
          >
            <Box key={DASHBOARD_PANEL_KEYS.KPI_TRENDS} sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}>
              <DashboardPanelShell title="KPI Trends">
                <KpiTrendPanels
                  spark={kpiSpark}
                  trendWindow={trendWindow}
                  onOpenTrends={openTrends}
                />
              </DashboardPanelShell>
            </Box>

            <Box key={DASHBOARD_PANEL_KEYS.TOP_PREFIXES} sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}>
              <DashboardPanelShell title="Top Prefixes">
                <TopPrefixesPanel month={strMonth} year={strYear} limit={5} />
              </DashboardPanelShell>
            </Box>

            <Box key={DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION} sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}>
              <DashboardPanelShell title="Threat Distribution">
                <ThreatDistributionPanel dangerCounts={data.danger_counts} />
              </DashboardPanelShell>
            </Box>
          </ResponsiveGridLayout>
        </Box>
      </Container>
    </Box>
  );
}