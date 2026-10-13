import * as React from "react";
import { Alert, Box, Button, Container, Stack } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { alpha } from "@mui/material/styles";
import { useQuery } from "@tanstack/react-query";
import { Skeleton } from "boneyard-js/react";
import { Responsive, type Layout } from "react-grid-layout/legacy";
import { getBreakpointFromWidth, useContainerWidth } from "react-grid-layout";

import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";

import { getMe } from "@/api/auth";
import {
  getDashboardScopes,
  getDashboardSummary,
  type DashboardScopes,
  type DashboardSummary,
} from "@/features/dashboard/api";
import {
  BREAKPOINTS,
  COLS,
  DEFAULT_LAYOUTS,
  PANEL_KEYS,
  ROW_HEIGHT,
  layoutStorageKey,
  loadLayouts,
  saveLayouts,
  type ResponsiveLayouts,
} from "@/features/dashboard/layout";
import { useThemeMode } from "@/styles/ThemeStore";

import OverviewHeader from "@/features/dashboard/components/OverviewHeader";
import { monthName, scopeLabel, scopeName } from "@/features/dashboard/format";
import ThreatDistributionPanel from "@/features/dashboard/components/ThreatDistributionPanel";
import TopPrefixesPanel from "@/features/dashboard/components/TopPrefixesPanel";
import { DashboardEmpty, DashboardLoading } from "@/features/dashboard/components/StatePanels";
import KpiTrendPanels from "@/features/dashboard/components/KpiTrendPanels";

function monthNameShort(m: number) {
  return new Date(2000, m - 1, 1).toLocaleString("en", { month: "short" });
}

const OVERALL_ONLY: DashboardScopes = { default: "ALL", options: [{ key: "ALL", label: "Overall" }] };
const GRID_MARGIN: [number, number] = [16, 16];
const GRID_PADDING: [number, number] = [0, 0];

function httpStatus(error: unknown): number | undefined {
  return (error as { response?: { status?: number } } | null)?.response?.status;
}

/**
 * Grid shell. D1: the grid mounts only once its container is measured (no
 * first paint at the library's 1280px default), and layouts are persisted
 * only from a user drag/resize stop. onLayoutChange is deliberately not
 * wired: it also fires for width/breakpoint/theme changes, and feeding it
 * back into state and storage is what wrote layouts nobody chose.
 */
function DashboardGrid(props: {
  layouts: ResponsiveLayouts;
  onUserLayout: (breakpoint: string, layout: Layout) => void;
  children: React.ReactNode;
}) {
  const { width, containerRef, mounted } = useContainerWidth({ measureBeforeMount: true });
  const { onUserLayout } = props;
  const onStop = React.useCallback(
    (layout: Layout) => onUserLayout(getBreakpointFromWidth(BREAKPOINTS, width), layout),
    [onUserLayout, width]
  );

  return (
    <div ref={containerRef}>
      {mounted ? (
        <Responsive
          className="dashboard-layout"
          width={width}
          layouts={props.layouts}
          breakpoints={BREAKPOINTS}
          cols={COLS}
          rowHeight={ROW_HEIGHT}
          margin={GRID_MARGIN}
          containerPadding={GRID_PADDING}
          compactType="vertical"
          preventCollision={false}
          isDraggable
          isResizable
          useCSSTransforms
          draggableHandle=".dashboard-panel-drag-handle"
          onDragStop={onStop}
          onResizeStop={onStop}
        >
          {props.children}
        </Responsive>
      ) : null}
    </div>
  );
}

// DashboardPanelShell: drag handle + visible affordances

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
        "& .react-resizable-handle": {
          opacity: 0,
          transition: "opacity .18s ease",
        },
        "&:hover .react-resizable-handle": {
          opacity: 1,
        },
      }}
    >
      <DragHandle />

      <Box sx={{ flex: 1, minHeight: 0, overflow: "hidden" }}>
        {children}
      </Box>
    </Box>
  );
});

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

// Global grid CSS overrides: injected once

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

// Page

export default function DashboardPage() {
  const now = new Date();

  const [month, setMonth] = React.useState(now.getMonth() + 1);
  const [year, setYear] = React.useState(now.getFullYear());
  // null = the backend's default for this user (from /scopes/).
  const [scope, setScope] = React.useState<string | null>(null);
  const [refusedScope, setRefusedScope] = React.useState<string | null>(null);

  const meQuery = useQuery({ queryKey: ["me"], queryFn: getMe, retry: false });
  const scopesQuery = useQuery({
    queryKey: ["dashboardScopes"],
    queryFn: getDashboardScopes,
    retry: false,
    staleTime: 5 * 60_000,
  });

  const scopes = scopesQuery.data ?? OVERALL_ONLY;
  const scopeKey = scope ?? scopes.default;
  const optionFor = (key: string) =>
    scopes.options.find((o) => o.key === key) ?? { key, label: key };

  const userId = meQuery.data?.id;
  const storageKey = layoutStorageKey(userId);
  const [layouts, setLayouts] = React.useState<ResponsiveLayouts>(() => loadLayouts(storageKey));
  const [prevStorageKey, setPrevStorageKey] = React.useState(storageKey);
  if (storageKey !== prevStorageKey) {
    setPrevStorageKey(storageKey);
    setLayouts(loadLayouts(storageKey));
  }

  const summaryQuery = useQuery<DashboardSummary>({
    queryKey: ["dashboardSummary", month, year, scopeKey],
    queryFn: () => getDashboardSummary({ month, year, scope: scopeKey }),
    enabled: !scopesQuery.isPending,
    retry: false,
  });

  // A scope the backend refuses (403) or no longer understands (400) falls
  // back to the default with a message, never a blank page.
  const status = httpStatus(summaryQuery.error);
  if (summaryQuery.isError && (status === 403 || status === 400) && scope !== null && scope !== scopes.default) {
    setRefusedScope(scope);
    setScope(null);
  }

  const changeScope = (key: string) => {
    setRefusedScope(null);
    setScope(key);
  };

  const data = summaryQuery.data;
  const shownScope = data?.scope ?? optionFor(scopeKey);
  const pageSubtitle = `${monthName(data?.month ?? month)} ${data?.year ?? year} · ${scopeName(shownScope)}`;
  const noCountry = scopesQuery.isSuccess && !scopes.options.some((o) => o.key === "OWN_COUNTRY");

  const kpiSpark = React.useMemo(() => {
    const m = data?.month ?? month;
    const y = data?.year ?? year;
    const [pm, py] = m === 1 ? [12, y - 1] : [m - 1, y];
    return {
      labels: [`${monthNameShort(pm)} ${String(py).slice(-2)}`, `${monthNameShort(m)} ${String(y).slice(-2)}`],
      // Only reports have a previous-month figure in the summary.
      submissions: [data ? data.previous.reports : null, data ? data.reports : null],
      reporters: [null, data ? data.reporters : null],
      newUsers: [null, data ? data.new_users : null],
    };
  }, [data, month, year]);

  const isEmpty = data !== undefined && data.reports === 0;
  const isInitialLoading = meQuery.isLoading || scopesQuery.isPending || summaryQuery.isLoading;

  const persistLayout = React.useCallback(
    (breakpoint: string, layout: Layout) => {
      const next = { ...layouts, [breakpoint]: layout };
      setLayouts(next);
      saveLayouts(storageKey, next);
    },
    [layouts, storageKey]
  );

  const resetLayouts = () => {
    setLayouts(DEFAULT_LAYOUTS);
    saveLayouts(storageKey, DEFAULT_LAYOUTS);
  };

  const strMonth = String(month).padStart(2, "0");
  const strYear = String(year);

  return (
    <Box>
      <GridStyles />

      <OverviewHeader
        title="Dashboard"
        subtitle={pageSubtitle}
        note={noCountry ? "No country is set on your profile." : undefined}
        month={month}
        year={year}
        onMonthChange={setMonth}
        onYearChange={setYear}
        scopeOptions={scopesQuery.isPending ? null : scopes.options}
        scope={scopeKey}
        onScopeChange={changeScope}
        onRefresh={() => summaryQuery.refetch()}
      />

      {refusedScope ? (
        <Container maxWidth="xl" sx={{ pt: 2 }}>
          <Alert severity="warning" onClose={() => setRefusedScope(null)}>
            {scopeLabel(optionFor(refusedScope).label)} is not available to you. Showing{" "}
            {scopeLabel(optionFor(scopes.default).label)} instead.
          </Alert>
        </Container>
      ) : null}

      {summaryQuery.isError ? (
        <Container maxWidth="xl" sx={{ py: 3 }}>
          <Alert
            severity="error"
            action={
              <Button color="inherit" size="small" onClick={() => summaryQuery.refetch()}>
                Retry
              </Button>
            }
          >
            Dashboard data unavailable.
          </Alert>
        </Container>
      ) : (
        <Skeleton name="dashboard-page" loading={isInitialLoading} fallback={<DashboardLoading />} animate="shimmer">
          <Container maxWidth="xl" sx={{ py: 2.5 }}>
            {isEmpty ? (
              <DashboardEmpty
                title="No reports in this period"
                description={`Nothing was reported in ${pageSubtitle}. Try another month or scope.`}
                onRefresh={() => summaryQuery.refetch()}
              />
            ) : null}

            <Box sx={{ opacity: isEmpty ? 0.5 : 1, pointerEvents: isEmpty ? "none" : "auto" }}>
              <Stack direction="row" sx={{ mb: 1, alignItems: "center", justifyContent: "space-between" }}>
                <Box>
                  <Box sx={{ fontWeight: 700, fontSize: 14 }}>Overview</Box>
                  <Box sx={{ color: "text.secondary", fontSize: 12 }}>
                    KPI evolution for {monthName(data?.month ?? month)} {data?.year ?? year}
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

              <DashboardGrid layouts={layouts} onUserLayout={persistLayout}>
                <Box
                  key={PANEL_KEYS.KPI_TRENDS}
                  className="dashboard-draggable-panel"
                  sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}
                >
                  <DashboardPanelShell title="KPI Trends">
                    <KpiTrendPanels spark={kpiSpark} />
                  </DashboardPanelShell>
                </Box>

                <Box
                  key={PANEL_KEYS.TOP_PREFIXES}
                  className="dashboard-draggable-panel"
                  sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}
                >
                  <DashboardPanelShell title="Top Prefixes">
                    <TopPrefixesPanel month={strMonth} year={strYear} limit={5} />
                  </DashboardPanelShell>
                </Box>

                <Box
                  key={PANEL_KEYS.THREAT_DISTRIBUTION}
                  className="dashboard-draggable-panel"
                  sx={{ height: "100%", minHeight: 0, overflow: "hidden" }}
                >
                  <DashboardPanelShell title="Threat Distribution">
                    <ThreatDistributionPanel dangerCounts={data?.danger_counts ?? EMPTY_DANGER} />
                  </DashboardPanelShell>
                </Box>
              </DashboardGrid>
            </Box>
          </Container>
        </Skeleton>
      )}
    </Box>
  );
}

const EMPTY_DANGER = { failure: 0, safe: 0, inconclusive: 0, suspicious: 0, dangerous: 0, malicious: 0 };
