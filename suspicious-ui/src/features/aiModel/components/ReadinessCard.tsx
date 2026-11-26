import { Box, Button, Paper, Stack, Typography } from "@mui/material";
import { CheckCircle as CheckCircleIcon, RadioButtonUnchecked as RadioButtonUncheckedIcon } from "@mui/icons-material";

import { CODE_TEXT } from "../labels";

/** Each requirement in plain words. recheck_* are three faces of one requirement and show once. */
const ROWS: { key: string; done: string; todo: string }[] = [
  { key: "too_young", done: "The shadow has run long enough", todo: "The shadow has not run long enough yet" },
  { key: "too_few_results", done: "Enough live mails were compared", todo: "More live mails need to be compared" },
  { key: "unreviewed_flips", done: "Risky verdict changes are reviewed", todo: "Review the risky verdict changes" },
  { key: "unreviewed_campaigns", done: "Alert differences are reviewed", todo: "Review the alert differences" },
  { key: "recheck", done: "The quality check passed and is recent", todo: "Run the quality check (Recheck)" },
  { key: "profile_window", done: "The campaign settings are covered", todo: "Wait for the campaign settings window to be covered" },
  { key: "job_running", done: "No training job is running", todo: "Wait for the running training job to end" },
];

type Props = { conditions: string[]; busy: boolean; onPromote(): void };

export function ReadinessCard({ conditions, busy, onPromote }: Props) {
  const unmet = (key: string) =>
    key === "recheck" ? conditions.some((c) => c.startsWith("recheck_")) : conditions.includes(key);
  const left = ROWS.filter((r) => unmet(r.key)).length + (conditions.includes("not_shadow") ? 1 : 0);
  const ready = conditions.length === 0;
  return (
    <Paper variant="outlined" sx={{ p: 2 }} aria-label="Promotion readiness" role="region">
      <Stack direction={{ xs: "column", sm: "row" }} sx={{ justifyContent: "space-between", alignItems: { sm: "center" }, gap: 1 }}>
        <Typography variant="h6" component="h3">
          {ready ? "Ready to promote" : `Not ready yet: ${left} thing${left === 1 ? "" : "s"} left`}
        </Typography>
        <Button variant="contained" disabled={!ready || busy} onClick={onPromote}>
          Promote
        </Button>
      </Stack>
      <Box component="ul" aria-label="Promotion conditions" sx={{ listStyle: "none", m: 0, mt: 1, p: 0 }}>
        {ROWS.map((r) => {
          const todo = unmet(r.key);
          return (
            <Stack component="li" key={r.key} direction="row" spacing={1} sx={{ alignItems: "center", py: 0.25 }}>
              {todo ? <RadioButtonUncheckedIcon fontSize="small" color="warning" aria-hidden /> : <CheckCircleIcon fontSize="small" color="success" aria-hidden />}
              <Typography variant="body2">
                <Box component="span" sx={visuallyHidden}>{todo ? "To do: " : "Done: "}</Box>
                {todo ? r.todo : r.done}
              </Typography>
            </Stack>
          );
        })}
        {conditions.includes("not_shadow") && (
          <Typography component="li" variant="body2" sx={{ listStyle: "none" }}>{CODE_TEXT.not_shadow}</Typography>
        )}
      </Box>
    </Paper>
  );
}

const visuallyHidden = { position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0 0 0 0)", whiteSpace: "nowrap" } as const;
