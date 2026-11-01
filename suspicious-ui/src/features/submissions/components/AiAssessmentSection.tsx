import { Alert, Chip, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";
import type { AiAssessment } from "../api";

const TIER_MEANING = {
  high: "The model is confident",
  medium: "The model leans this way, check the evidence",
  low: "The model is unsure, rely on the other evidence",
} as const;

const TIER_LABEL = { high: "High", medium: "Medium", low: "Low" } as const;

// Similarity is a raw number server-side; never print it, only the rows.
export function AiAssessmentSection({ assessment: a }: { assessment: AiAssessment }) {
  return (
    <Stack spacing={1}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }} useFlexGap>
        <Typography variant="subtitle2">{a.result}</Typography>
        {a.sub_class && <Chip size="small" variant="outlined" label={a.sub_class} />}
        {a.tier ? (
          <Chip size="small" label={TIER_LABEL[a.tier]} />
        ) : (
          <Typography variant="caption" color="text.secondary">Confidence not calibrated</Typography>
        )}
      </Stack>
      {a.tier && (
        <Typography variant="body2">{TIER_MEANING[a.tier]}</Typography>
      )}
      {a.tier === "low" && a.runner_up && (
        <Typography variant="body2">Runner-up: {a.runner_up.result}</Typography>
      )}
      <Typography variant="caption" color="text.secondary">
        Model {a.model_version}, reads the mail: {a.reads}.
      </Typography>
      {a.campaign && (
        <Typography variant="body2">{`Campaign ${a.campaign.ref}, ${a.campaign.size} mails`}</Typography>
      )}
      {a.cross_check.disagrees && <Alert severity="warning">AI disagrees with the evidence</Alert>}
      {a.cross_check.facts.map((f, i) => (
        <Typography key={i} variant="body2">{f.text}</Typography>
      ))}
      {a.similar_cases.length > 0 && (
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Similar case</TableCell><TableCell>Label</TableCell><TableCell>Provenance</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {a.similar_cases.map((s, i) => (
              <TableRow key={s.case_id ?? i}>
                <TableCell>{s.case_id != null ? `#${s.case_id}` : "—"}</TableCell>
                <TableCell>{s.label ?? "—"}</TableCell>
                <TableCell>{s.provenance ?? "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Stack>
  );
}
