import { List, ListItem, ListItemText } from "@mui/material";

import { CODE_TEXT } from "../labels";

/** Every condition the server can report, so a met one shows as done. */
// recheck_* are three faces of one requirement; show it once.
const ROWS = ["too_young", "too_few_results", "unreviewed_flips", "unreviewed_campaigns", "recheck", "profile_window", "job_running"];
const DONE: Record<string, string> = {
  too_young: "The shadow period has run its minimum days.",
  too_few_results: "Enough live results have been compared.",
  unreviewed_flips: "All critical verdict flips are reviewed.",
  unreviewed_campaigns: "All campaign changes are reviewed.",
  recheck: "The gate recheck passed and is recent.",
  profile_window: "The campaign profile window is covered.",
  job_running: "No retrain or recheck job is running.",
};

export function PromotionConditions({ conditions }: { conditions: string[] }) {
  const unmet = (r: string) =>
    r === "recheck" ? conditions.find((c) => c.startsWith("recheck_")) : conditions.includes(r) ? r : undefined;
  return (
    <List dense aria-label="Promotion conditions">
      {ROWS.map((r) => {
        const code = unmet(r);
        return (
          <ListItem key={r}>
            <ListItemText primary={code ? `Not met: ${CODE_TEXT[code] ?? code}` : `Done: ${DONE[r]}`} />
          </ListItem>
        );
      })}
      {conditions.includes("not_shadow") && (
        <ListItem><ListItemText primary={`Not met: ${CODE_TEXT.not_shadow}`} /></ListItem>
      )}
    </List>
  );
}
