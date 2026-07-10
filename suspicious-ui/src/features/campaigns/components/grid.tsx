import * as React from "react";
import { Box } from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";


function DragDots({ dotColor }: { dotColor: string }) {
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: "repeat(3, 5px)",
        gridTemplateRows: "repeat(2, 5px)",
        gap: "3px",
        pointerEvents: "none",
      }}
    >
      {Array.from({ length: 6 }).map((_, i) => (
        <Box
          key={i}
          sx={{
            width: 4,
            height: 4,
            borderRadius: 99,
            backgroundColor: dotColor,
          }}
        />
      ))}
    </Box>
  );
}

function DragHandle() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const dotColor = isDark
    ? "rgba(255,255,255,.38)"
    : alpha(theme.palette.divider, 0.9);

  return (
    <Box
      className="campaigns-drag-handle"
      title="Drag to move"
      sx={{
        flexShrink: 0,
        height: 22,
        mb: 0.5,
        borderRadius: "8px 8px 0 0",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        cursor: "grab",
        userSelect: "none",
        opacity: 0,
        transition: "opacity .18s ease, background .18s ease",
        background: isDark
          ? alpha("#fff", 0.04)
          : alpha(theme.palette.grey[400], 0.1),
        "&:active": {
          cursor: "grabbing",
          background: isDark
            ? alpha("#fff", 0.08)
            : alpha(theme.palette.grey[400], 0.18),
        },
      }}
    >
      <DragDots dotColor={dotColor} />
    </Box>
  );
}

export const PanelShell = React.memo(function PanelShell({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Box
      sx={{
        height: "100%",
        minHeight: 0,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        "& .react-resizable-handle": {
          opacity: 0,
          transition: "opacity .18s ease",
        },
        "&:hover .react-resizable-handle": { opacity: 1 },
      }}
    >
      <DragHandle />
      <Box sx={{ flex: 1, minHeight: 0, overflow: "hidden" }}>{children}</Box>
    </Box>
  );
});

export function GridStyles() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const handleColor = isDark
    ? "rgba(255,255,255,.55)"
    : alpha(theme.palette.grey[500], 0.7);
  const handleBg = isDark
    ? "rgba(30,41,59,0.92)"
    : alpha(theme.palette.background.paper, 0.95);
  const handleBorder = isDark
    ? "1px solid rgba(255,255,255,.12)"
    : `1px solid ${alpha(theme.palette.divider, 0.7)}`;
  const placeholderBg = isDark
    ? "rgba(56,189,248,.14)"
    : alpha(theme.palette.primary.main, 0.08);
  const placeholderBorder = isDark
    ? "rgba(56,189,248,.45)"
    : alpha(theme.palette.primary.main, 0.4);

  return (
    <style>{`
      .react-resizable-handle {
        position: absolute;
        width: 20px;
        height: 20px;
        bottom: 4px;
        right: 4px;
        padding: 0;
        border-radius: 6px;
        background: ${handleBg};
        border: ${handleBorder};
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: se-resize;
        z-index: 10;
        transition: opacity .18s ease;
      }
      .react-resizable-handle::after {
        content: '';
        display: block;
        width: 8px;
        height: 8px;
        border-right: 2px solid ${handleColor};
        border-bottom: 2px solid ${handleColor};
        border-radius: 0 0 3px 0;
      }
      .react-resizable-handle-se {
        background-image: none !important;
        background-position: unset !important;
      }
      .react-grid-item.react-grid-placeholder {
        background: ${placeholderBg} !important;
        border: 2px dashed ${placeholderBorder} !important;
        border-radius: 12px !important;
        opacity: 1 !important;
      }
      .react-grid-item:hover .campaigns-drag-handle {
        opacity: 1 !important;
      }
      .react-grid-item:hover .react-resizable-handle {
        opacity: 1 !important;
      }
    `}</style>
  );
}
