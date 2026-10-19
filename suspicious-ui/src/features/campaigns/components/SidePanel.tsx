import * as React from "react";
import { Box, ButtonBase, Link, Stack, Typography } from "@mui/material";
import { Link as RouterLink } from "react-router";

import type { CampaignNeighbours, CampaignRow, NeighbourItem, PcaPoint } from "@/features/campaigns/api";
import { caseIdToCampaign, nearest } from "@/features/campaigns/geometry";
import { classKey, classLabel, formatDay, formatFullDay } from "@/features/campaigns/utils";
import ClassChip from "./ClassChip";

const NEAREST = 8;

function Row({ item, detail, onSelectCases }: { item: NeighbourItem; detail: string; onSelectCases: (ids: string[]) => void }) {
  const id = item.suspicious_case_id;
  return (
    <Box component="li" sx={{ py: 1, borderTop: "1px solid", borderColor: "divider" }}>
      {/* The subject selects the point; the case link is a separate control (no link inside a button). */}
      <ButtonBase
        disabled={!id}
        onClick={() => id && onSelectCases([id])}
        sx={{ display: "block", textAlign: "left", width: "100%", borderRadius: 1, "&:hover": { bgcolor: "action.hover" } }}
      >
        <Typography variant="body2" sx={{ fontWeight: 600, overflowWrap: "anywhere" }}>
          {item.mail_subject ?? "No subject"}
        </Typography>
        <Typography variant="caption" color="text.secondary" component="span">
          {detail}
        </Typography>
      </ButtonBase>
      <Stack direction="row" spacing={1} sx={{ mt: 0.5, alignItems: "center" }}>
        <ClassChip k={classKey(item.label)} label={classLabel(item.label)} />
        {id ? (
          <Link component={RouterLink} to={`/investigation?open=${encodeURIComponent(id)}`} variant="body2">
            Case {id}
          </Link>
        ) : null}
      </Stack>
    </Box>
  );
}

const asItem = (p: PcaPoint, distance: number): NeighbourItem => ({
  suspicious_case_id: p.suspicious_case_id,
  mail_subject: p.mail_subject,
  label: p.label,
  date: p.date,
  score: distance,
  nearest_dangerous_case_id: null,
  nearest_dangerous_similarity: null,
});

/** The one message picked in the map: what it is, which campaign lists it, and its closest neighbours in the three plotted components. */
function SelectedMessage({ point, points, campaigns, onSelectCases }: { point: PcaPoint; points: PcaPoint[]; campaigns: CampaignRow[]; onSelectCases: (ids: string[]) => void }) {
  const headingId = React.useId();
  const id = point.suspicious_case_id;
  const campaign = React.useMemo(() => {
    const at = id ? caseIdToCampaign(campaigns).get(id) : undefined;
    return at === undefined ? null : campaigns[at].name;
  }, [campaigns, id]);
  const near = React.useMemo(() => nearest(points, points.indexOf(point), NEAREST), [points, point]);

  return (
    <Box component="section" aria-labelledby={headingId} sx={{ mb: 2, pb: 1, borderBottom: "1px solid", borderColor: "divider" }}>
      <Typography variant="subtitle2" component="h3" id={headingId}>
        Selected message
      </Typography>
      <Typography variant="body2" sx={{ fontWeight: 600, overflowWrap: "anywhere", mt: 0.5 }}>
        {point.mail_subject ?? "No subject"}
      </Typography>
      <Stack direction="row" useFlexGap spacing={1} sx={{ mt: 0.5, alignItems: "center", flexWrap: "wrap" }}>
        <ClassChip k={classKey(point.label)} label={classLabel(point.label)} />
        {point.date ? (
          <Typography variant="caption" color="text.secondary">
            {formatFullDay(point.date)}
          </Typography>
        ) : null}
        {id ? (
          <Link component={RouterLink} to={`/investigation?open=${encodeURIComponent(id)}`} variant="body2">
            Case {id}
          </Link>
        ) : null}
      </Stack>
      {campaign ? (
        <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 0.5, overflowWrap: "anywhere" }}>
          Campaign: {campaign}
        </Typography>
      ) : null}

      <Typography variant="subtitle2" component="h3" sx={{ mt: 1.5 }}>
        Nearest in this 3D view
      </Typography>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 0.5 }}>
        Distance in the 3-component view, not the full embedding.
      </Typography>
      {near.length ? (
        <Box component="ol" aria-label="Nearest messages" sx={{ m: 0, p: 0, listStyle: "none" }}>
          {near.map((n) => (
            <Row
              key={n.index}
              item={asItem(points[n.index], n.distance)}
              detail={[points[n.index].date ? formatDay(points[n.index].date!) : null, `distance ${n.distance.toFixed(3)}`].filter(Boolean).join("; ")}
              onSelectCases={onSelectCases}
            />
          ))}
        </Box>
      ) : (
        <Typography variant="body2" color="text.secondary">
          No other message in the sample.
        </Typography>
      )}
    </Box>
  );
}

function Section(props: { title: string; caption: string; items: NeighbourItem[]; detail: (i: NeighbourItem) => string; onSelectCases: (ids: string[]) => void }) {
  return (
    <Box component="section" sx={{ mb: 2 }}>
      <Typography variant="subtitle2" component="h3">
        {props.title}
      </Typography>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 1 }}>
        {props.caption}
      </Typography>
      {props.items.length ? (
        <Box component="ul" sx={{ m: 0, p: 0, listStyle: "none" }}>
          {props.items.map((item, i) => (
            <Row key={`${item.suspicious_case_id ?? "none"}-${i}`} item={item} detail={props.detail(item)} onSelectCases={props.onSelectCases} />
          ))}
        </Box>
      ) : (
        <Typography variant="body2" color="text.secondary">
          Nothing to review in this sample.
        </Typography>
      )}
    </Box>
  );
}

/** Near-known-bad and novel lists; every number and threshold in the copy comes from the payload. */
export default function SidePanel({
  neighbours: n,
  onSelectCases,
  points = [],
  selectedCaseIds = [],
  campaigns = [],
}: {
  neighbours: CampaignNeighbours;
  onSelectCases: (ids: string[]) => void;
  /** The map's sample, to describe the one selected message and find its neighbours. */
  points?: PcaPoint[];
  selectedCaseIds?: string[];
  campaigns?: CampaignRow[];
}) {
  const selected = selectedCaseIds.length === 1 ? points.find((p) => p.suspicious_case_id === selectedCaseIds[0]) : undefined;
  return (
    <>
      {selected ? <SelectedMessage point={selected} points={points} campaigns={campaigns} onSelectCases={onSelectCases} /> : null}
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
        Closeness in the embedding space is a hint, not proof of a campaign.
      </Typography>
      <Section
        title="Near known bad"
        caption={`Not dangerous, but at least ${Math.round(n.bad_share_threshold * 100)}% of their ${n.k} nearest messages are.`}
        items={n.near_known_bad}
        onSelectCases={onSelectCases}
        detail={(i) =>
          [
            `${Math.round(i.score * 100)}% of ${n.k} nearest are dangerous`,
            i.nearest_dangerous_similarity === null ? null : `similarity ${i.nearest_dangerous_similarity.toFixed(2)} to the nearest dangerous mail`,
          ]
            .filter(Boolean)
            .join("; ")
        }
      />
      <Section
        title="Novel"
        caption={`Sent in the last ${n.novel_window_days} days, with a nearest neighbour farther away than for ${n.novelty_percentile}% of the sample.`}
        items={n.novel}
        onSelectCases={onSelectCases}
        detail={(i) => [i.date ? formatDay(i.date) : null, `distance ${i.score.toFixed(2)} to the nearest message`].filter(Boolean).join("; ")}
      />
    </>
  );
}
