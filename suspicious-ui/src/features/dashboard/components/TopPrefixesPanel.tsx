// file: src/features/dashboard/components/TopPrefixesPanel.tsx
import * as React from "react";
import { Box, Chip, Divider, Stack, Typography } from "@mui/material";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

type PrefixItem = { label: string; value: number };

export default function TopPrefixesPanel(props: { data: PrefixItem[] }) {
  return (
    <Box
      sx={{
        borderRadius: 3,
        border: "1px solid",
        borderColor: "divider",
        bgcolor: "background.paper",
        p: 2,
      }}
    >
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Typography sx={{ fontWeight: 900, fontSize: 14 }}>Top prefixes</Typography>
        <Chip size="small" label="Top 10" variant="outlined" />
      </Stack>

      <Divider sx={{ mb: 1.5 }} />

      <Box sx={{ height: 320 }}>
        {props.data.length ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={props.data}>
              <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
              <XAxis dataKey="label" tick={{ fontSize: 12 }} interval={0} height={56} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="value" radius={[8, 8, 0, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <Stack sx={{ height: "100%" }} alignItems="center" justifyContent="center">
            <Typography color="text.secondary" variant="body2">
              No prefixes for this period
            </Typography>
          </Stack>
        )}
      </Box>

      <Box sx={{ mt: 1, color: "text.secondary", fontSize: 12 }}>
        Tip: use the ranked table below for search + quick actions.
      </Box>
    </Box>
  );
}
