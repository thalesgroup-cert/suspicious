/**
 * ScreenshotPanel — shows the analyzer's captured page screenshot next to the
 * verdict on an investigation detail page.
 *
 * The backend serves the PNG at `/api/cases/<id>/screenshot.png` (auth via the
 * httpOnly knox cookie, so a plain <img src> works in-app). The case detail and
 * each observable surface a `screenshot_url` that is either the path or `null`.
 *
 * Unlike MailPreview this has no click-to-load / retry machinery: it only ever
 * renders on the detail page (one instance, not per list row), so an eager <img>
 * with a skeleton while it loads is enough. On `null` or a load error we show a
 * muted "No screenshot available" note instead of a broken-image icon.
 */
import { useState } from "react";
import { Box, Skeleton, Typography } from "@mui/material";

export function ScreenshotPanel({ src, label }: { src: string | null; label: string }) {
  const [state, setState] = useState<"loading" | "ok" | "error">(src ? "loading" : "error");

  if (!src || state === "error") {
    return (
      <Box sx={{ p: 2, bgcolor: "action.hover", borderRadius: 1 }}>
        <Typography variant="body2" color="text.secondary">
          No screenshot available
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="caption" color="text.secondary">
        {label}
      </Typography>
      {state === "loading" && <Skeleton variant="rectangular" height={240} />}
      <Box
        component="img"
        src={src}
        alt={label}
        onLoad={() => setState("ok")}
        onError={() => setState("error")}
        sx={{
          display: "block",
          // Keep the <img> in the DOM (and the a11y tree) while it loads so the
          // skeleton shows above it; reveal once the bytes are in.
          opacity: state === "ok" ? 1 : 0,
          height: state === "ok" ? "auto" : 0,
          maxWidth: "100%",
          border: "1px solid",
          borderColor: "divider",
        }}
      />
    </Box>
  );
}
