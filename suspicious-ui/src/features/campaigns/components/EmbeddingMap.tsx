import * as React from "react";
import { Button, Stack, Typography } from "@mui/material";

import type { CampaignNeighbours, PcaPoint } from "@/features/campaigns/api";
import Embedding2D from "./Embedding2D";
import PointTable from "./PointTable";

export type EmbeddingMapProps = {
  points: PcaPoint[];
  explainedVariance: number[];
  /** For Task 4 (highlighting the review lists in the 3D map); unused by the 2D map. */
  neighbours?: CampaignNeighbours;
  selectedCaseIds: string[];
  onSelectCases: (caseIds: string[]) => void;
};

/** The map slot: the 2D scatter for now (Task 4 adds the lazy 3D map here), with a table alternative. */
export default function EmbeddingMap({ points, selectedCaseIds, onSelectCases }: EmbeddingMapProps) {
  const [asTable, setAsTable] = React.useState(false);
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

  return (
    <>
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
        <Button size="small" onClick={() => setAsTable((v) => !v)} aria-pressed={asTable}>
          Table view
        </Button>
      </Stack>
      {asTable ? <PointTable points={points} /> : <Embedding2D points={points} selectedCaseIds={selectedCaseIds} />}
    </>
  );
}
