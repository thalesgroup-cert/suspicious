import { useState } from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Chip,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { ExpandMoreOutlined } from "@mui/icons-material";
import { alpha, useTheme } from "@mui/material/styles";

import { analyzeUrl, type UrlArtifact } from "@/features/submissions/api";
import { CopyIconButton } from "@/shared/components/CopyIconButton";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function registeredDomain(address: string): string {
  try {
    const host = new URL(address).hostname.replace(/^www\./, "");
    const parts = host.split(".");
    return parts.length > 2 ? parts.slice(-2).join(".") : host;
  } catch {
    return address;
  }
}

const STATUS_COLOR: Record<
  UrlArtifact["analysis_status"],
  "default" | "success" | "info" | "warning"
> = {
  analyzed: "success",
  reused: "info",
  pending: "warning",
  skipped: "default",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export interface UrlGroupListProps {
  submissionId: number;
  urls: UrlArtifact[];
}

export function UrlGroupList({ submissionId, urls }: UrlGroupListProps) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  // Track which url ids have an in-flight analyze request
  const [busyIds, setBusyIds] = useState<Set<number>>(new Set());
  // Optimistically flip status to "pending" after triggering analyze
  const [optimisticStatus, setOptimisticStatus] = useState<
    Map<number, UrlArtifact["analysis_status"]>
  >(new Map());

  const handleAnalyze = async (urlId: number) => {
    setBusyIds((prev) => new Set(prev).add(urlId));
    try {
      await analyzeUrl(submissionId, urlId);
      setOptimisticStatus((prev) => new Map(prev).set(urlId, "pending"));
    } finally {
      setBusyIds((prev) => {
        const next = new Set(prev);
        next.delete(urlId);
        return next;
      });
    }
  };

  // Group by registered domain, preserving insertion order
  const groups = new Map<string, UrlArtifact[]>();
  for (const u of urls) {
    const domain = registeredDomain(u.address);
    if (!groups.has(domain)) groups.set(domain, []);
    groups.get(domain)!.push(u);
  }

  if (groups.size === 0) return null;

  return (
    <Box>
      <Stack spacing={1}>
        {[...groups.entries()].map(([domain, items]) => {
          // Resolve each item with its optimistic status
          const resolved = items.map((u) => ({
            ...u,
            analysis_status: optimisticStatus.get(u.id) ?? u.analysis_status,
          }));

          // Sort by interestingness desc
          const sorted = [...resolved].sort(
            (a, b) => b.interestingness - a.interestingness,
          );

          // Count by status
          const counts = resolved.reduce<Record<string, number>>((acc, u) => {
            acc[u.analysis_status] = (acc[u.analysis_status] ?? 0) + 1;
            return acc;
          }, {});

          return (
            <Accordion
              key={domain}
              disableGutters
              defaultExpanded
              sx={{
                borderRadius: 2.5,
                border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
                background: isDark
                  ? alpha("#fff", 0.02)
                  : alpha(theme.palette.background.paper, 0.5),
                overflow: "hidden",
                "&:before": { display: "none" },
              }}
            >
              <AccordionSummary
                expandIcon={
                  <ExpandMoreOutlined sx={{ fontSize: 18, opacity: 0.6 }} />
                }
                sx={{
                  px: 1.75,
                  py: 0.6,
                  minHeight: 0,
                  "& .MuiAccordionSummary-content": { my: 0.5 },
                  background: isDark
                    ? alpha("#fff", 0.03)
                    : alpha(theme.palette.background.paper, 0.7),
                  "&:hover": {
                    background: isDark
                      ? alpha("#fff", 0.05)
                      : alpha(theme.palette.primary.main, 0.04),
                  },
                  transition: "background .15s ease",
                }}
              >
                <Stack
                  direction="row"
                  spacing={1}
                  sx={{ alignItems: "center", flexWrap: "wrap", flex: 1, mr: 1 }}
                >
                  <Typography
                    variant="body2"
                    sx={{ fontWeight: 700, fontSize: 12.5 }}
                  >
                    {domain}
                  </Typography>
                  <Typography
                    variant="caption"
                    color="text.disabled"
                    sx={{ fontSize: 11 }}
                  >
                    {items.length} URL{items.length !== 1 ? "s" : ""}
                  </Typography>
                  {/* Status breakdown chips */}
                  {(
                    [
                      ["analyzed", counts.analyzed],
                      ["reused", counts.reused],
                      ["skipped", counts.skipped],
                      ["pending", counts.pending],
                    ] as [UrlArtifact["analysis_status"], number | undefined][]
                  )
                    .filter(([, n]) => n)
                    .map(([status, n]) => (
                      <Chip
                        key={status}
                        label={`${n} ${status}`}
                        size="small"
                        color={STATUS_COLOR[status]}
                        variant="outlined"
                        sx={{
                          height: 18,
                          fontSize: 10,
                          fontWeight: 800,
                          "& .MuiChip-label": { px: 0.75 },
                        }}
                      />
                    ))}
                </Stack>
              </AccordionSummary>

              <AccordionDetails sx={{ p: 1.25 }}>
                <Stack spacing={0.5}>
                  {sorted.map((u) => {
                    const isBusy = busyIds.has(u.id);
                    const effectiveStatus =
                      optimisticStatus.get(u.id) ?? u.analysis_status;

                    return (
                      <Box
                        key={u.id}
                        sx={{
                          display: "flex",
                          alignItems: "center",
                          gap: 1,
                          px: 1,
                          py: 0.5,
                          borderRadius: 1.5,
                          background: isDark
                            ? alpha("#fff", 0.02)
                            : alpha(theme.palette.background.default, 0.5),
                          border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.1 : 0.3)}`,
                        }}
                      >
                        {/* Status chip */}
                        <Chip
                          label={effectiveStatus}
                          size="small"
                          color={STATUS_COLOR[effectiveStatus]}
                          variant="outlined"
                          sx={{
                            height: 18,
                            fontSize: 10,
                            fontWeight: 800,
                            flexShrink: 0,
                            "& .MuiChip-label": { px: 0.75 },
                          }}
                        />

                        {/* URL text */}
                        <Tooltip title={u.address} placement="top-start">
                          <Typography
                            variant="body2"
                            sx={{
                              flex: 1,
                              fontSize: 12,
                              fontWeight: 500,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {u.address}
                          </Typography>
                        </Tooltip>

                        {/* Copy URL to clipboard */}
                        <CopyIconButton text={u.address} title="Copy URL" />

                        {/* Analyze button — only on skipped rows */}
                        {effectiveStatus === "skipped" && (
                          <Button
                            size="small"
                            variant="outlined"
                            disabled={isBusy}
                            onClick={() => handleAnalyze(u.id)}
                            sx={{
                              textTransform: "none",
                              fontWeight: 800,
                              borderRadius: 2,
                              fontSize: 11,
                              py: 0.15,
                              px: 1,
                              minWidth: 0,
                              flexShrink: 0,
                            }}
                          >
                            {isBusy ? "Analyzing…" : "Analyze"}
                          </Button>
                        )}
                      </Box>
                    );
                  })}
                </Stack>
              </AccordionDetails>
            </Accordion>
          );
        })}
      </Stack>
    </Box>
  );
}
