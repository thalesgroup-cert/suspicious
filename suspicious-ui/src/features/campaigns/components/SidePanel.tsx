import { Box, ButtonBase, Link, Stack, Typography } from "@mui/material";
import { Link as RouterLink } from "react-router";

import { ResultChip } from "@/shared/components/ResultChip";
import type { CampaignNeighbours, NeighbourItem } from "@/features/campaigns/api";
import { formatDay } from "@/features/campaigns/utils";

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
        <ResultChip result={item.label} size="small" />
        {id ? (
          <Link component={RouterLink} to={`/investigation?open=${encodeURIComponent(id)}`} variant="body2">
            Case {id}
          </Link>
        ) : null}
      </Stack>
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
export default function SidePanel({ neighbours: n, onSelectCases }: { neighbours: CampaignNeighbours; onSelectCases: (ids: string[]) => void }) {
  return (
    <>
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
