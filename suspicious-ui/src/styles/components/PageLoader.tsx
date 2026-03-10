// src/components/ui/PageLoader.tsx

import * as React from "react";
import { Box, Card, CardContent, CircularProgress, Stack, Typography } from "@mui/material";

export default function PageLoader(props: { label?: string }) {
  return (
    <Box
      sx={{
        minHeight: "50vh",
        display: "grid",
        placeItems: "center",
      }}
    >
      <Card
        sx={{
          borderRadius: 3,
          border: "1px solid rgba(255,255,255,.10)",
          background:
            "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))",
          px: 3,
          py: 2,
        }}
      >
        <CardContent>
          <Stack spacing={2} alignItems="center">
            <CircularProgress
                size={26}
                sx={{
                    color: "#38BDF8",
                }}
            />

            <Typography
              sx={{
                fontSize: 13,
                fontWeight: 600,
                color: "text.secondary",
              }}
            >
              {props.label ?? "Loading data…"}
            </Typography>
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
}