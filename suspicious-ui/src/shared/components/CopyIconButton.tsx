import * as React from "react";
import { IconButton, Tooltip } from "@mui/material";
import ContentCopyOutlined from "@mui/icons-material/ContentCopyOutlined";

export function CopyIconButton({ text, title = "Copy" }: { text: string; title?: string }) {
  return (
    <Tooltip title={title}>
      <IconButton
        size="small"
        onClick={async (e) => {
          e.stopPropagation();
          await navigator.clipboard.writeText(text);
        }}
      >
        <ContentCopyOutlined fontSize="small" />
      </IconButton>
    </Tooltip>
  );
}
