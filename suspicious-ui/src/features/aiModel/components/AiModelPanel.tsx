import * as React from "react";
import { Box, Tab, Tabs, Typography } from "@mui/material";

// Tasks 7 to 11 fill the tabs.
const TABS = ["Overview", "Candidate", "Shadow", "Versions", "Ledger"] as const;

export function AiModelPanel() {
  const id = React.useId();
  const [tab, setTab] = React.useState<(typeof TABS)[number]>("Overview");
  return (
    <Box>
      <Typography variant="subtitle1" component="h3" sx={{ mb: 1 }}>
        Model lifecycle
      </Typography>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} aria-label="AI model" variant="scrollable">
        {TABS.map((t) => (
          <Tab key={t} value={t} label={t} id={`${id}-tab-${t}`} aria-controls={`${id}-panel-${t}`} />
        ))}
      </Tabs>
      <Box role="tabpanel" id={`${id}-panel-${tab}`} aria-labelledby={`${id}-tab-${tab}`} sx={{ pt: 2 }} />
    </Box>
  );
}
