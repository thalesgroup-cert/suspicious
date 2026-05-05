// src/pages/DashboardPage.tsx
import * as React from "react";
import { Alert, Box, Container, Stack } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { alpha } from "@mui/material/styles";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Responsive, WidthProvider, type Layout } from "react-grid-layout/legacy";

import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";

import { getMe } from "@/api/auth";
import { getDashboardSummary, type DashboardSummary } from "@/features/dashboard/api";
import { useThemeMode } from "@/styles/ThemeStore";

import OverviewHeader from "@/features/dashboard/components/OverviewHeader";
import ThreatDistributionPanel from "@/features/dashboard/components/ThreatDistributionPanel";
import TopPrefixesPanel from "@/features/dashboard/components/TopPrefixesPanel";
import { DashboardEmpty, DashboardLoading } from "@/features/dashboard/components/StatePanels";
import KpiTrendPanels from "@/features/dashboard/components/KpiTrendPanels";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    if (m <= 0) { m = 12; y -= 1; }
  }
  return out.reverse();
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EMPTY_SUMMARY: DashboardSummary = {
  month: 1,
  year: 1970,
  scope: "ALL",
  kpis: { new_users: 0, total_reporters: 0, total_cases: 0 },
  danger_counts: {
    failure: 0, safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0, malicious: 0,
  },
  top_prefixes: [],
};

const DASHBOARD_PANEL_KEYS = {
  KPI_TRENDS: "kpi-trends",
  TOP_PREFIXES: "top-prefixes",
  THREAT_DISTRIBUTION: "threat-distribution",
} as const;

const DASHBOARD_BREAKPOINTS = { lg: 1200, md: 900, sm: 600, xs: 0 };
const DASHBOARD_COLS = { lg: 12, md: 12, sm: 6, xs: 1 };

// Row height unit in px. All h values below are in these units.
// rowHeight=32 → h:6 = 192px (KPI row), h:14 = 448px (bottom row — tall enough for all legend items)
const ROW_HEIGHT = 32;

// Bottom row height — tall enough to show the full threat legend without scrolling.
// At 32px/unit: 14 units = 448px. Increase if needed.
const BOTTOM_H = 14;
const BOTTOM_MIN_H = 10;

type ResponsiveLayouts = Partial<Record<string, Layout>>;

// Layouts: KPI row is full-width, bottom row splits Top Prefixes (8 cols) and
// Threat Distribution (4 cols) at the SAME height so they align perfectly.
const DEFAULT_DASHBOARD_LAYOUTS: ResponsiveLayouts = {
  lg: [
    { i: DASHBOARD_PANEL_KEYS.KPI_TRENDS,          x: 0,  y: 0,          w: 12, h: 6,       minW: 6,  minH: 4 },
    { i: DASHBOARD_PANEL_KEYS.TOP_PREFIXES,         x: 0,  y: 6,          w: 8,  h: BOTTOM_H, minW: 4, minH: BOTTOM_MIN_H },
    { i: DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION,  x: 8,  y: 6,          w: 4,  h: BOTTOM_H, minW: 4, minH: BOTTOM_MIN_H },
  ],
  md: [
    { i: DASHBOARD_PANEL_KEYS.KPI_TRENDS,          x: 0,  y: 0,          w: 12, h: 6,       minW: 6,  minH: 4 },
    { i: DASHBOARD_PANEL_KEYS.TOP_PREFIXES,         x: 0,  y: 6,          w: 7,  h: BOTTOM_H, minW: 4, minH: BOTTOM_MIN_H },
    { i: DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION,  x: 7,  y: 6,          w: 5,  h: BOTTOM_H, minW: 4, minH: BOTTOM_MIN_H },
  ],
  sm: [
    { i: DASHBOARD_PANEL_KEYS.KPI_TRENDS,          x: 0,  y: 0,                   w: 6, h: 6,       minH: 4 },
    { i: DASHBOARD_PANEL_KEYS.TOP_PREFIXES,         x: 0,  y: 6,                   w: 6, h: BOTTOM_H, minH: BOTTOM_MIN_H },
    { i: DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION,  x: 0,  y: 6 + BOTTOM_H,        w: 6, h: BOTTOM_H, minH: BOTTOM_MIN_H },
  ],
  xs: [
    { i: DASHBOARD_PANEL_KEYS.KPI_TRENDS,          x: 0,  y: 0,                          w: 1, h: 6,       minH: 4 },
    { i: DASHBOARD_PANEL_KEYS.TOP_PREFIXES,         x: 0,  y: 6,                          w: 1, h: BOTTOM_H, minH: BOTTOM_MIN_H },
    { i: DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION,  x: 0,  y: 6 + BOTTOM_H,               w: 1, h: BOTTOM_H, minH: BOTTOM_MIN_H },
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
  try { window.localStorage.setItem(storageKey, JSON.stringify(layouts)); } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// DashboardPanelShell — drag handle + visible affordances
// ---------------------------------------------------------------------------

type DashboardPanelShellProps = { title: string; children: React.ReactNode };

const DashboardPanelShell = React.memo(function DashboardPanelShell({
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
        // Make the resize handle visible via a global override scoped to this panel
        "& .react-resizable-handle": {
          opacity: 0,
          transition: "opacity .18s ease",
        },
        "&:hover .react-resizable-handle": {
          opacity: 1,
        },
      }}
    >
      {/* Drag handle bar — visible on hover */}
      <DragHandle />

      <Box sx={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
        {children}
      </Box>
    </Box>
  );
});

// Visible drag handle strip at the top of every panel
function DragHandle() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Box
      className="dashboard-panel-drag-handle"
      title="Drag to move"
      sx={{
        flexShrink: 0,
        height: 22,
        mb: 0.5,
        mx: 0,
        borderRadius: "8px 8px 0 0",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        cursor: "grab",
        userSelect: "none",
        opacity: 0,
        transition: "opacity .18s ease, background .18s ease",
        background: isDark
          ? alpha("#fff", 0.04)
          : alpha(theme.palette.grey[400], 0.1),
        // Show on parent hover — handled by sibling selector in DashboardPanelShell
        ".dashboard-draggable-panel:hover &": {
          opacity: 1,
        },
        "&:active": {
          cursor: "grabbing",
          background: isDark
            ? alpha("#fff", 0.08)
            : alpha(theme.palette.grey[400], 0.18),
        },
      }}
    >
      {/* 6-dot grip */}
      <DragDots isDark={isDark} dividerColor={theme.palette.divider} />
    </Box>
  );
}

function DragDots({ isDark, dividerColor }: { isDark: boolean; dividerColor: string }) {
  const dotColor = isDark ? "rgba(255,255,255,.38)" : alpha(dividerColor, 0.9);

  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: "repeat(3, 5px)",
        gridTemplateRows: "repeat(2, 5px)",
        gap: "3px",
        pointerEvents: "none",
      }}
    >
      {Array.from({ length: 6 }).map((_, i) => (
        <Box
          key={i}
          sx={{
            width: 4,
            height: 4,
            borderRadius: 99,
            backgroundColor: dotColor,
          }}
        />
      ))}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Global grid CSS overrides — injected once
// ---------------------------------------------------------------------------

function GridStyles() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const { capabilities } = useThemeMode();
  const { effects } = capabilities;

  const handleColor = isDark ? "rgba(255,255,255,.55)" : alpha(theme.palette.grey[500], 0.7);
  const handleBg = isDark
    ? "rgba(30,41,59,0.92)"
    : alpha(theme.palette.background.paper, 0.95);
  const handleBorder = isDark
    ? "1px solid rgba(255,255,255,.12)"
    : `1px solid ${alpha(theme.palette.divider, 0.7)}`;

  // Drag placeholder color follows theme
  const placeholderBg = effects.hasNeonEffect
    ? "rgba(0,229,255,.1)"
    : effects.hasSolarEffect
    ? "rgba(201,164,76,.1)"
    : effects.hasPortalEffect
    ? "rgba(74,144,217,.1)"
    : effects.hasAlertStates
    ? "rgba(55,214,199,.1)"
    : effects.hasEmberEffect
    ? "rgba(255,140,0,.1)"
    : effects.hasBloomEffect
    ? "rgba(236,72,153,.08)"
    : isDark
    ? "rgba(56,189,248,.14)"
    : alpha(theme.palette.primary.main, 0.08);

  const placeholderBorder = effects.hasNeonEffect
    ? "2px dashed rgba(0,229,255,.4)"
    : effects.hasSolarEffect
    ? "2px dashed rgba(201,164,76,.45)"
    : effects.hasPortalEffect
    ? "2px dashed rgba(74,144,217,.5)"
    : effects.hasAlertStates
    ? "2px dashed rgba(55,214,199,.45)"
    : effects.hasEmberEffect
    ? "2px dashed rgba(255,140,0,.4)"
    : effects.hasBloomEffect
    ? "2px dashed rgba(236,72,153,.35)"
    : isDark
    ? "2px dashed rgba(56,189,248,.45)"
    : `2px dashed ${alpha(theme.palette.primary.main, 0.4)}`;

  return (
    <style>{`
      /* Resize handle: small square in bottom-right corner */
      .react-resizable-handle {
        position: absolute;
        width: 20px;
        height: 20px;
        bottom: 4px;
        right: 4px;
        padding: 0;
        border-radius: 6px;
        background: ${handleBg};
        border: ${handleBorder};
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: se-resize;
        z-index: 10;
        transition: opacity .18s ease;
      }

      /* Draw a resize icon using a CSS border trick */
      .react-resizable-handle::after {
        content: '';
        display: block;
        width: 8px;
        height: 8px;
        border-right: 2px solid ${handleColor};
        border-bottom: 2px solid ${handleColor};
        border-radius: 0 0 3px 0;
      }

      /* Override the default background-image the library sets */
      .react-resizable-handle-se {
        background-image: none !important;
        background-position: unset !important;
      }

      /* Dragging placeholder */
      .react-grid-item.react-grid-placeholder {
        background: ${placeholderBg} !important;
        border: ${placeholderBorder} !important;
        border-radius: 12px !important;
        opacity: 1 !important;
      }

      /* Show drag handle strip on grid item hover */
      .react-grid-item:hover .dashboard-panel-drag-handle {
        opacity: 1 !important;
      }

      /* Show resize handle on grid item hover */
      .react-grid-item:hover .react-resizable-handle {
        opacity: 1 !important;
      }
    `}</style>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function DashboardPage() {
  const now = new Date();

  const [openKpiTrends, setOpenKpiTrends] = React.useState(false);
  const [selectedMetric, setSelectedMetric] = React.useState<string | undefined>(undefined);

  const [month, setMonth] = React.useState(now.getMonth() + 1);
  const [year, setYear] = React.useState(now.getFullYear());
  const [scope, setScope] = React.useState<string>("ALL");
  const [trendWindow, setTrendWindow] = React.useState<number>(6);

  const meQuery = useQuery({ queryKey: ["me"], queryFn: getMe, retry: false });

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
    queryFn: async () => getDashboardSummary({ month, year, scope: effectiveScope }),
    retry: false,
  });

  const data: DashboardSummary = summaryQuery.data ?? {
    ...EMPTY_SUMMARY, month, year, scope: effectiveScope,
  };

  const historyParams = React.useMemo(
    () => getMonthWindow(month, year, Math.max(1, trendWindow)),
    [month, year, trendWindow]
  );

  const historyQueries = useQueries({
    queries: historyParams.map(({ month: hm, year: hy }) => ({
      queryKey: ["dashboardSummary", hm, hy, effectiveScope, "history"],
      queryFn: async () => getDashboardSummary({ month: hm, year: hy, scope: effectiveScope }),
      retry: false,
      staleTime: 30_000,
    })),
  });

  const pageSubtitle = React.useMemo(() => {
    return `${monthName(data.month)} ${data.year}${isCiso ? ` • Scope: ${data.scope}` : ""}`;
  }, [data.month, data.year, data.scope, isCiso]);

  const kpiSpark = React.useMemo(() => {
    const labels = historyParams.map(
      (p) => `${monthNameShort(p.month)} ${String(p.year).slice(-2)}`
    );
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
      {/* Inject grid CSS overrides — theme-aware, re-renders on theme switch */}
      <GridStyles />

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
          {/* Section header */}
          <Stack
            direction="row"
            sx={{ mb: 1, alignItems: "center", justifyContent: "space-between" }}
          >
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
            rowHeight={ROW_HEIGHT}
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
            {/* KPI Trends */}
            <Box
              key={DASHBOARD_PANEL_KEYS.KPI_TRENDS}
              className="dashboard-draggable-panel"
              sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}
            >
              <DashboardPanelShell title="KPI Trends">
                <KpiTrendPanels
                  spark={kpiSpark}
                  trendWindow={trendWindow}
                  onOpenTrends={openTrends}
                />
              </DashboardPanelShell>
            </Box>

            {/* Top Prefixes */}
            <Box
              key={DASHBOARD_PANEL_KEYS.TOP_PREFIXES}
              className="dashboard-draggable-panel"
              sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}
            >
              <DashboardPanelShell title="Top Prefixes">
                <TopPrefixesPanel month={strMonth} year={strYear} limit={5} />
              </DashboardPanelShell>
            </Box>

            {/* Threat Distribution */}
            <Box
              key={DASHBOARD_PANEL_KEYS.THREAT_DISTRIBUTION}
              className="dashboard-draggable-panel"
              sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}
            >
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