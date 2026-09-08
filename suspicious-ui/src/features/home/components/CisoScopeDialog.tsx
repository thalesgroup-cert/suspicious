import * as React from "react";
import {
  Alert,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  Typography,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { ApartmentOutlined, PublicOutlined } from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getHomeSummary, setCisoScope } from "@/features/home/api";

/**
 * The "select your management scope" modal shown to a CISO who has no scope
 * set yet — on first connection (Home) and when they open Investigation.
 * Forced modal: no dismiss until a scope is confirmed.
 */
export function CisoScopeDialog({ open }: { open: boolean }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const qc = useQueryClient();

  const [scopeChoice, setScopeChoice] = React.useState("");

  const now = React.useMemo(() => new Date(), []);
  const summaryQuery = useQuery({
    queryKey: ["homeSummary", now.getMonth() + 1, now.getFullYear()],
    queryFn: () => getHomeSummary({ month: now.getMonth() + 1, year: now.getFullYear() }),
    enabled: open,
    retry: false,
  });

  const suggested = summaryQuery.data?.suggested_scopes ?? {};

  const scopeMutation = useMutation({
    mutationFn: setCisoScope,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["me"] });
      qc.invalidateQueries({ queryKey: ["homeSummary"] });
      qc.invalidateQueries({ queryKey: ["investigation"] });
    },
  });

  return (
    <Dialog open={open} maxWidth="sm" fullWidth>
      <DialogTitle>Select your management scope</DialogTitle>
      <DialogContent>
        <Stack spacing={1.25} sx={{ mt: 1 }}>
          <Typography color="text.secondary">
            This controls dashboards, investigations and submission visibility for your CISO view.
          </Typography>

          <Card
            sx={{
              borderRadius: 3,
              border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.7)}`,
              background: isDark
                ? "linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03))"
                : `linear-gradient(180deg, ${alpha("#fff", 0.88)}, ${alpha(theme.palette.grey[50], 0.96)})`,
            }}
          >
            <CardContent>
              <Stack spacing={1}>
                <Typography sx={{ fontWeight: 900 }}>Suggested scopes</Typography>

                <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                  {suggested.region ? (
                    <Chip
                      icon={<PublicOutlined />}
                      label={`Region: ${suggested.region}`}
                      clickable
                      onClick={() => setScopeChoice(suggested.region ?? "")}
                      variant={scopeChoice === suggested.region ? "filled" : "outlined"}
                    />
                  ) : null}

                  {suggested.country ? (
                    <Chip
                      icon={<ApartmentOutlined />}
                      label={`Country: ${suggested.country}`}
                      clickable
                      onClick={() => setScopeChoice(suggested.country ?? "")}
                      variant={scopeChoice === suggested.country ? "filled" : "outlined"}
                    />
                  ) : null}

                  {suggested.gbu ? (
                    <Chip
                      label={`GBU: ${suggested.gbu}`}
                      clickable
                      onClick={() => setScopeChoice(suggested.gbu ?? "")}
                      variant={scopeChoice === suggested.gbu ? "filled" : "outlined"}
                    />
                  ) : null}

                  <Chip
                    label="All cases"
                    clickable
                    onClick={() => setScopeChoice("ALL")}
                    variant={scopeChoice === "ALL" ? "filled" : "outlined"}
                  />

                  {!suggested.region && !suggested.country && !suggested.gbu ? (
                    <Chip label="No org-unit suggestions" variant="outlined" />
                  ) : null}
                </Stack>

                <Typography variant="caption" color="text.secondary">
                  You can change it later from your profile if your responsibilities change.
                </Typography>

                {scopeMutation.isError ? (
                  <Alert severity="error">Failed to set scope.</Alert>
                ) : null}
              </Stack>
            </CardContent>
          </Card>
        </Stack>
      </DialogContent>

      <DialogActions>
        <Button
          variant="contained"
          disabled={!scopeChoice || scopeMutation.isPending}
          onClick={() => scopeMutation.mutate({ scope: scopeChoice })}
          sx={{ borderRadius: 3, textTransform: "none", fontWeight: 950 }}
        >
          {scopeMutation.isPending ? "Saving…" : "Confirm scope"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
