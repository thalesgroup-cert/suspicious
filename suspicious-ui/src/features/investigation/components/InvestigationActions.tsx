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
  LinkOutlined,
  MoreHoriz,
  NorthEastOutlined,
  ReplayOutlined,
} from "@mui/icons-material";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useSnackbar } from "notistack";

import { pushSubmissionToTheHive } from "@/features/submissions/api";
import { getEnabledConnectors } from "@/features/settings/components/connectors";

/** The decision actions: Edit verdict and, when the TheHive connector is enabled, Push to TheHive. */
export function PrimaryActions({ id, detailsReady, onEdit, compact }: {
  id: number;
  /** Details loaded without error: editing and pushing need them. */
  detailsReady: boolean;
  onEdit: () => void;
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
    onSuccess: (res) => {
      enqueueSnackbar(
        res.status === "updated"
          ? "Updated the existing TheHive alert."
          : "Created an alert in TheHive.",
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
      <Tooltip title={detailsReady ? "" : "Available once the details load."} disableHoverListener={detailsReady}>
        <span>
          <Button variant="contained" size={size} startIcon={<EditOutlined />} disabled={!detailsReady} onClick={onEdit} sx={{ whiteSpace: "nowrap" }}>
            Edit verdict
          </Button>
        </span>
      </Tooltip>
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
        <MenuItem disabled={!detailsReady || !terminal} onClick={run(onRedo)}>
          {icon(<ReplayOutlined fontSize="small" />)}
          <ListItemText secondary={detailsReady && !terminal ? "Case is still being analyzed." : undefined}>Redo analysis</ListItemText>
        </MenuItem>
      </Menu>
    </>
  );
}
