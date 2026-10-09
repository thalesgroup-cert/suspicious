import * as React from "react";
import { IconButton, ListItemIcon, ListItemText, Menu, MenuItem, Tooltip } from "@mui/material";
import { useNavigate } from "react-router";
import { useSnackbar } from "notistack";
import {
  DescriptionOutlined,
  DownloadOutlined,
  FlagOutlined,
  LinkOutlined,
  ManageSearchOutlined,
  MoreHoriz,
} from "@mui/icons-material";

type Props = {
  id: number | string;
  /** Elevated users (CISO, CERT, Admin) can open the case in Investigation. */
  elevated?: boolean;
  /** Present only when the row can be challenged. */
  onChallenge?: () => void;
  /** Phones: "Full report" moves in here so the header stays one row. */
  includeFullReport?: boolean;
};

export function DrawerActions({ id, elevated, onChallenge, includeFullReport }: Props) {
  const [anchor, setAnchor] = React.useState<HTMLElement | null>(null);
  const navigate = useNavigate();
  const { enqueueSnackbar } = useSnackbar();
  const close = () => setAnchor(null);
  const run = (fn: () => void) => () => { close(); fn(); };
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
        {includeFullReport ? (
          <MenuItem onClick={run(() => window.open(`/api/cases/${id}/report/`, "_blank"))}>
            {icon(<DescriptionOutlined fontSize="small" />)}<ListItemText>Full report</ListItemText>
          </MenuItem>
        ) : null}
        <MenuItem onClick={run(() => window.open(`/api/cases/${id}/report.md`, "_blank"))}>
          {icon(<DownloadOutlined fontSize="small" />)}<ListItemText>Markdown report</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={run(() => {
            void navigator.clipboard
              .writeText(`${window.location.origin}/submissions?open=${id}`)
              .then(() => enqueueSnackbar("Link copied", { variant: "success" }));
          })}
        >
          {icon(<LinkOutlined fontSize="small" />)}<ListItemText>Copy link</ListItemText>
        </MenuItem>
        {elevated ? (
          <MenuItem onClick={run(() => navigate(`/investigation?open=${id}`))}>
            {icon(<ManageSearchOutlined fontSize="small" />)}<ListItemText>Open in Investigation</ListItemText>
          </MenuItem>
        ) : null}
        {onChallenge ? (
          <MenuItem onClick={run(onChallenge)}>
            {icon(<FlagOutlined fontSize="small" />)}<ListItemText>Challenge</ListItemText>
          </MenuItem>
        ) : null}
      </Menu>
    </>
  );
}
