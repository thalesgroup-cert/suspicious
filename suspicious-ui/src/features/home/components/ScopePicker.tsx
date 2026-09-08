import * as React from "react";
import {
  Alert,
  Button,
  Checkbox,
  FormControlLabel,
  FormGroup,
  Stack,
  Typography,
} from "@mui/material";
import { ApartmentOutlined, PublicOutlined, BusinessOutlined } from "@mui/icons-material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getHomeSummary, setCisoScope } from "@/features/home/api";

const ALL = "ALL";

/** Parse a stored scope string into the checkbox model. */
function parse(scope: string | undefined): { all: boolean; groups: string[] } {
  const s = (scope ?? "").trim();
  if (!s || s.toUpperCase() === ALL) return { all: s.toUpperCase() === ALL, groups: [] };
  return { all: false, groups: s.split("|").map((p) => p.trim()).filter(Boolean) };
}

function serialize(all: boolean, groups: string[]): string {
  return all ? ALL : [...groups].sort().join("|");
}

/**
 * The management-scope multi-select, shared by the forced first-run dialog
 * (CisoScopeDialog) and the "Management scope" profile tab.
 *
 * A CISO may pick any combination of their own org units (region / country /
 * GBU) — cases are matched if the reporter is in *any* selected group — or
 * "All cases". Server-side `validate_scope` rejects anything outside those.
 */
export function ScopePicker({
  currentScope,
  onSaved,
  onCancel,
  enabled = true,
}: {
  currentScope?: string;
  onSaved?: () => void;
  onCancel?: () => void;
  /** Skip fetching suggestions until the picker is actually visible. */
  enabled?: boolean;
}) {
  const qc = useQueryClient();

  const now = React.useMemo(() => new Date(), []);
  const summaryQuery = useQuery({
    queryKey: ["homeSummary", now.getMonth() + 1, now.getFullYear()],
    queryFn: () => getHomeSummary({ month: now.getMonth() + 1, year: now.getFullYear() }),
    enabled,
    retry: false,
  });
  const suggested = summaryQuery.data?.suggested_scopes ?? {};

  const options = React.useMemo(
    () =>
      [
        { key: suggested.region, label: `Region: ${suggested.region}`, icon: <PublicOutlined fontSize="small" /> },
        { key: suggested.country, label: `Country: ${suggested.country}`, icon: <ApartmentOutlined fontSize="small" /> },
        { key: suggested.gbu, label: `GBU: ${suggested.gbu}`, icon: <BusinessOutlined fontSize="small" /> },
      ].filter((o): o is { key: string; label: string; icon: React.ReactElement } => !!o.key),
    [suggested.region, suggested.country, suggested.gbu],
  );

  // Callers that need to re-seed from a changed `currentScope` (the dialog on
  // reopen) pass a `key` to remount instead — keeps this state dead simple.
  const initial = React.useMemo(() => parse(currentScope), [currentScope]);
  const [all, setAll] = React.useState(initial.all);
  const [groups, setGroups] = React.useState<string[]>(initial.groups);

  const toggleGroup = (key: string) =>
    setGroups((prev) => (prev.includes(key) ? prev.filter((g) => g !== key) : [...prev, key]));

  const next = serialize(all, groups);
  const dirty = next !== serialize(initial.all, initial.groups);
  const empty = !all && groups.length === 0;

  const mutation = useMutation({
    mutationFn: setCisoScope,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["me"] });
      qc.invalidateQueries({ queryKey: ["homeSummary"] });
      qc.invalidateQueries({ queryKey: ["investigation"] });
      onSaved?.();
    },
  });

  return (
    <Stack spacing={1.5}>
      <Typography color="text.secondary">
        This controls dashboards, investigations and submission visibility for your CISO view.
        Cases are shown when the reporter belongs to any scope you select.
      </Typography>

      <FormGroup>
        {options.map((o) => (
          <FormControlLabel
            key={o.key}
            control={
              <Checkbox
                checked={all || groups.includes(o.key)}
                disabled={all}
                onChange={() => toggleGroup(o.key)}
              />
            }
            label={
              <Stack direction="row" spacing={0.75} sx={{ alignItems: "center" }}>
                {o.icon}
                <span>{o.label}</span>
              </Stack>
            }
          />
        ))}
        {options.length === 0 && !summaryQuery.isPending ? (
          <Typography variant="body2" color="text.secondary">
            No org-unit suggestions available for your profile.
          </Typography>
        ) : null}
        <FormControlLabel
          control={
            <Checkbox
              checked={all}
              onChange={() => {
                setAll((v) => !v);
                setGroups([]);
              }}
            />
          }
          label="All cases (no restriction)"
        />
      </FormGroup>

      {mutation.isError ? <Alert severity="error">Failed to save scope.</Alert> : null}

      <Stack direction="row" spacing={1} sx={{ justifyContent: "flex-end" }}>
        {onCancel ? (
          <Button
            onClick={onCancel}
            disabled={mutation.isPending}
            sx={{ borderRadius: 3, textTransform: "none", fontWeight: 800 }}
          >
            Cancel
          </Button>
        ) : null}
        <Button
          variant="contained"
          disabled={empty || !dirty || mutation.isPending}
          onClick={() => mutation.mutate({ scope: next })}
          sx={{ borderRadius: 3, textTransform: "none", fontWeight: 950 }}
        >
          {mutation.isPending ? "Saving…" : "Save scope"}
        </Button>
      </Stack>
    </Stack>
  );
}
