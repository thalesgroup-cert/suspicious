import * as React from "react";
import { Box, Skeleton, Stack, ToggleButton, ToggleButtonGroup, Button, Typography } from "@mui/material";

import type { CampaignRow, PcaPoint } from "@/features/campaigns/api";
import { MAP_HEIGHT } from "@/features/campaigns/utils";
import { mapCaption } from "@/features/campaigns/mapModel";
import { detectWebGL } from "@/features/campaigns/mapSupport";
import Embedding2D from "./Embedding2D";
import PointTable from "./PointTable";

// three.js, react-three-fiber and drei are about 250 kB gzip: fetched only when this page draws the 3D map.
const EmbeddingMap3D = React.lazy(() => import("./EmbeddingMap3D"));

export type EmbeddingMapProps = {
  points: PcaPoint[];
  explainedVariance: number[];
  /** The period's campaigns, for the map's campaign colours. */
  campaigns?: CampaignRow[];
  /** The sample size asked of the backend, for the caption. */
  sampleLimit?: number;
  selectedCaseIds: string[];
  onSelectCases: (caseIds: string[]) => void;
};

/** Catches a render error in the 3D map (no WebGL context, a failed chunk fetch, a lost context) and tells the parent. */
class Boundary extends React.Component<{ onError: () => void; children: React.ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidCatch() {
    this.props.onError();
  }
  render() {
    return this.state.failed ? null : this.props.children;
  }
}

function Loading() {
  return (
    <Box role="status" sx={{ position: "relative" }}>
      <Skeleton variant="rounded" animation={false} sx={{ height: MAP_HEIGHT, transform: "none" }} />
      <Typography variant="body2" color="text.secondary" sx={{ position: "absolute", inset: 0, display: "grid", placeItems: "center" }}>
        Loading the 3D map
      </Typography>
    </Box>
  );
}

/** The map slot: the 3D map when the browser can draw it, else the 2D scatter, with a table as the text alternative. */
export default function EmbeddingMap({ points, explainedVariance, campaigns, sampleLimit, selectedCaseIds, onSelectCases }: EmbeddingMapProps) {
  const [asTable, setAsTable] = React.useState(false);
  const [view, setView] = React.useState<"2d" | "3d">("3d");
  const [failed, setFailed] = React.useState(false);
  const shown = selectedCaseIds.length;
  const ids = new Set(selectedCaseIds);
  // The map is a sample: say how many of the selected cases it actually holds.
  const inSample = points.filter((p) => p.suspicious_case_id && ids.has(p.suspicious_case_id)).length;

  if (!points.length) {
    return (
      <Typography variant="body2" color="text.secondary">
        No messages with an embedding in the store.
      </Typography>
    );
  }

  // The 2D scatter is the fallback, so a third component is what 3D needs, WebGL is what it draws with.
  const hasThird = explainedVariance.length >= 3;
  const webgl = detectWebGL();
  const can3D = hasThird && webgl && !failed;
  const use3D = can3D && view === "3d";

  return (
    <>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 1 }}>
        {mapCaption(explainedVariance, use3D ? "3d" : "2d", sampleLimit)}
      </Typography>
      <Stack direction="row" useFlexGap spacing={1} sx={{ mb: 1, alignItems: "center", justifyContent: "flex-end", flexWrap: "wrap" }}>
        {/* Always mounted so a screen reader announces the count when it appears. */}
        <Stack role="status" aria-live="polite" direction="row" spacing={0.75} sx={{ mr: "auto", alignItems: "baseline" }}>
          {shown ? (
            <>
              <Typography variant="body2">{shown} selected</Typography>
              <Typography variant="body2" color="text.secondary">
                {inSample === shown ? "" : `${inSample} in the map sample`}
              </Typography>
            </>
          ) : null}
        </Stack>
        {shown ? (
          <Button size="small" onClick={() => onSelectCases([])}>
            Clear selection
          </Button>
        ) : null}
        {can3D ? (
          <ToggleButtonGroup size="small" exclusive aria-label="Map view" value={view} onChange={(_, v: "2d" | "3d" | null) => v && setView(v)}>
            <ToggleButton value="2d">2D view</ToggleButton>
            <ToggleButton value="3d">3D view</ToggleButton>
          </ToggleButtonGroup>
        ) : null}
        <ToggleButton size="small" value="table" selected={asTable} onChange={() => setAsTable((v) => !v)}>
          Table view
        </ToggleButton>
      </Stack>
      {hasThird && !can3D ? (
        <Typography role="status" variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          3D view unavailable, showing the 2D map.
        </Typography>
      ) : null}
      {asTable ? (
        <PointTable points={points} selectedCaseIds={selectedCaseIds} onSelectCases={onSelectCases} />
      ) : use3D ? (
        <Boundary onError={() => setFailed(true)}>
          <React.Suspense fallback={<Loading />}>
            <EmbeddingMap3D
              points={points}
              explainedVariance={explainedVariance}
              campaigns={campaigns ?? []}
              selectedCaseIds={selectedCaseIds}
              onSelectCases={onSelectCases}
            />
          </React.Suspense>
        </Boundary>
      ) : (
        <Embedding2D points={points} selectedCaseIds={selectedCaseIds} />
      )}
    </>
  );
}
