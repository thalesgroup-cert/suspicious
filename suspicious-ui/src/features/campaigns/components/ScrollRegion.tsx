import * as React from "react";
import { Box } from "@mui/material";
import { alpha, type SxProps, type Theme } from "@mui/material/styles";

/**
 * A named, keyboard-focusable region (so the arrow keys can scroll it) that shows a shadow along its
 * bottom edge only while more content continues below. Give it a height and `overflowY` through `sx`.
 */
export default function ScrollRegion({ label, sx, children }: { label: string; sx?: SxProps<Theme>; children: React.ReactNode }) {
  const ref = React.useRef<HTMLDivElement>(null);
  const [more, setMore] = React.useState(false);

  const measure = React.useCallback(() => {
    const el = ref.current;
    if (el) setMore(el.scrollHeight - el.scrollTop - el.clientHeight > 1);
  }, []);

  // Content changes re-render this component; size changes come from the observer.
  React.useLayoutEffect(measure);
  React.useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, [measure]);

  return (
    <Box
      ref={ref}
      role="region"
      aria-label={label}
      tabIndex={0}
      onScroll={measure}
      sx={[
        // An inset shadow keeps the focus outline intact, which a fade mask would clip.
        (theme) => ({ boxShadow: more ? `inset 0 -12px 10px -10px ${alpha(theme.palette.text.primary, 0.35)}` : "none" }),
        ...(Array.isArray(sx) ? sx : [sx]),
      ]}
    >
      {children}
    </Box>
  );
}
