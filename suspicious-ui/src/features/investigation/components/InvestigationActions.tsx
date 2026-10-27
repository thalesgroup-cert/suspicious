import * as React from "react";
import {
  Button,
  CircularProgress,
  IconButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Tooltip,
} from "@mui/material";
import {
  DescriptionOutlined,
  DownloadOutlined,
  EditOutlined,
  GavelOutlined,
  LinkOutlined,
  MoreHoriz,
  NorthEastOutlined,
  ReplayOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import { pushSubmissionToTheHive } from "@/features/submissions/api";
import { getEnabledConnectors } from "@/features/settings/components/connectors";
import { ensureContrast, flatten } from "@/shared/lib/contrast";

/**
 * The decision actions: Edit verdict (CERT and Admin), Challenge verdict (a CISO, for a user in their scope)
 * and, when the TheHive connector is enabled, Push to TheHive.
 */
export function PrimaryActions({ id, detailsReady, canEdit = true, onEdit, onChallenge, compact }: {
  id: number;
  /** Details loaded without error: editing, challenging and pushing need them. */
  detailsReady: boolean;
  /** The API refuses case edits from a CISO, so the button is not offered to them. */
  canEdit?: boolean;
  onEdit: () => void;
  /** Set only when the user may challenge this case; it also decides whether the button shows. */
  onChallenge?: () => void;
  /** Phones: small buttons so both fit beside the verdict chip more often. */
  compact?: boolean;
}) {
  const { enqueueSnackbar } = useSnackbar();
  const size = compact ? "small" : "medium";

  const enabledConnectorsQuery = useQuery({
    queryKey: ["enabledConnectors"],
    queryFn: getEnabledConnectors,
    staleTime: 60_000,
  });
  const theHiveEnabled = (enabledConnectorsQuery.data ?? []).includes("thehive");

  const pushMutation = useMutation({
    mutationFn: (caseId: number) => pushSubmissionToTheHive(caseId),
    // The pushed case's id, from the mutation itself: the message names the case that was actually sent.
    onSuccess: (res, caseId) => {
      enqueueSnackbar(
        res.status === "updated"
          ? `Updated the existing TheHive alert for #${caseId}.`
          : `Created an alert in TheHive for #${caseId}.`,
        { variant: "success" },
      );
    },
    onError: (err: unknown) => {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? "Push to TheHive failed.";
      enqueueSnackbar(detail, { variant: "error" });
    },
  });

  return (
    <>
      {canEdit ? (
        <Tooltip title={detailsReady ? "" : "Available once the details load."} disableHoverListener={detailsReady}>
          <span>
            <Button variant="contained" size={size} startIcon={<EditOutlined />} disabled={!detailsReady} onClick={onEdit} sx={{ whiteSpace: "nowrap" }}>
              Edit verdict
            </Button>
          </span>
        </Tooltip>
      ) : null}
      {onChallenge ? (
        <Button
          variant={canEdit ? "outlined" : "contained"}
          size={size}
          startIcon={<GavelOutlined />}
          disabled={!detailsReady}
          onClick={onChallenge}
          sx={{ whiteSpace: "nowrap" }}
        >
          Challenge verdict
        </Button>
      ) : null}
      {theHiveEnabled ? (
        <Button
          variant="outlined"
          size={size}
          startIcon={pushMutation.isPending ? <CircularProgress size={13} color="inherit" /> : <NorthEastOutlined />}
          disabled={!detailsReady || pushMutation.isPending}
          onClick={() => pushMutation.mutate(id)}
          sx={{ whiteSpace: "nowrap" }}
        >
          {pushMutation.isPending ? "Pushing…" : "Push to TheHive"}
        </Button>
      ) : null}
    </>
  );
}

/** The rarer actions, out of the way: reports, link, redo. */
export function MoreActions({ id, detailsReady, terminal, onRedo }: {
  id: number;
  detailsReady: boolean;
  /** DONE or CHALLENGED: redo is refused while analyzers still run. */
  terminal: boolean;
  onRedo: () => void;
}) {
  const { enqueueSnackbar } = useSnackbar();
  const [anchor, setAnchor] = React.useState<HTMLElement | null>(null);
  const close = () => setAnchor(null);
  const run = (fn: () => unknown) => () => { close(); void fn(); };
  const icon = (el: React.ReactNode) => <ListItemIcon>{el}</ListItemIcon>;
  const redoBlocked = !detailsReady || !terminal;

  return (
    <>
      <Tooltip title="More actions">
        <IconButton
          aria-label="More actions"
          aria-haspopup="menu"
          aria-expanded={anchor ? "true" : "false"}
          onClick={(e) => setAnchor(e.currentTarget)}
        >
          <MoreHoriz />
        </IconButton>
      </Tooltip>
      <Menu anchorEl={anchor} open={!!anchor} onClose={close}>
        <MenuItem onClick={run(() => window.open(`/api/cases/${id}/report/`, "_blank"))}>
          {icon(<DescriptionOutlined fontSize="small" />)}<ListItemText>Full report</ListItemText>
        </MenuItem>
        <MenuItem onClick={run(() => window.open(`/api/cases/${id}/report.md`, "_blank"))}>
          {icon(<DownloadOutlined fontSize="small" />)}<ListItemText>Markdown report</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={run(async () => {
            try {
              // navigator.clipboard is undefined on insecure origins.
              if (!navigator.clipboard?.writeText) throw new Error("no clipboard");
              await navigator.clipboard.writeText(`${window.location.origin}/investigation?open=${id}`);
              enqueueSnackbar("Link copied", { variant: "success" });
            } catch {
              enqueueSnackbar("Could not copy the link. Copy it from the address bar.", { variant: "error" });
            }
          })}
        >
          {icon(<LinkOutlined fontSize="small" />)}<ListItemText>Copy link</ListItemText>
        </MenuItem>
        {/* Same rule as the old button: needs loaded details and a finished case. A disabled item can't host a tooltip, so the reason is its second line. */}
        {/* Disabled without MUI's 0.38 item opacity: the reason line is the only explanation, so it keeps full contrast; the label and icon are greyed by hand. */}
        <MenuItem
          disabled={redoBlocked}
          onClick={run(onRedo)}
          sx={(t) => ({
            "&.Mui-disabled": { opacity: 1 },
            "&.Mui-disabled .MuiListItemIcon-root, &.Mui-disabled .MuiListItemText-primary": { color: t.palette.text.disabled },
            "& .MuiListItemText-secondary": { color: ensureContrast(flatten(t.palette.text.secondary, t.palette.background.paper), t.palette.background.paper) },
          })}
        >
          {icon(<ReplayOutlined fontSize="small" />)}
          <ListItemText secondary={detailsReady && !terminal ? "Case is still being analyzed." : undefined}>Redo analysis</ListItemText>
        </MenuItem>
      </Menu>
    </>
  );
}
