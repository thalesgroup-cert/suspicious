/**
 * MailPreview — renders the server-side .eml→png preview of a case.
 *
 * The backend exposes the preview at `/api/cases/<case_id>/mail-preview.png`
 * (auth via httpOnly knox cookie). Each Case serializer surfaces a
 * `mail_preview_url` flag that is either the path or `null`. We pass that
 * value here so the parent doesn't have to hard-code the URL shape.
 *
 * Two visual modes:
 *   - <MailPreview variant="thumbnail" .../>  small card for list rows
 *   - <MailPreview variant="full" .../>       full-width block for the
 *                                              investigation detail page
 *
 * Loading state shows a skeleton; broken-image / 404 falls back to a
 * subtle "No preview" hint instead of a broken image icon.
 */
import { useState } from "react";
import { Box, Skeleton, Typography, Stack } from "@mui/material";
import AttachEmailRoundedIcon from "@mui/icons-material/AttachEmailRounded";

export type MailPreviewProps = {
  /** Relative URL from the API, e.g. "/api/cases/42/mail-preview.png". `null`/empty = no preview. */
  url?: string | null;
  /** Visual size. Defaults to "thumbnail". */
  variant?: "thumbnail" | "full";
  /** Override label shown next to the icon (accessibility). */
  alt?: string;
};

const THUMB_WIDTH = 96;
const THUMB_HEIGHT = 124;

export default function MailPreview({ url, variant = "thumbnail", alt }: MailPreviewProps) {
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");

  if (!url) {
    return variant === "full" ? <NoPreviewBlock /> : null;
  }

  const isThumb = variant === "thumbnail";

  return (
    <Box
      sx={{
        position: "relative",
        width: isThumb ? THUMB_WIDTH : "100%",
        maxWidth: isThumb ? THUMB_WIDTH : 900,
        minHeight: isThumb ? THUMB_HEIGHT : 200,
        borderRadius: 1.5,
        overflow: "hidden",
        border: 1,
        borderColor: "divider",
        bgcolor: "background.paper",
        display: status === "error" ? "flex" : "block",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      {status === "loading" && (
        <Skeleton
          variant="rectangular"
          width="100%"
          height={isThumb ? THUMB_HEIGHT : 320}
          sx={{ position: "absolute", inset: 0 }}
        />
      )}
      {status !== "error" && (
        <Box
          component="img"
          src={url}
          alt={alt ?? "Email preview"}
          loading="lazy"
          onLoad={() => setStatus("ready")}
          onError={() => setStatus("error")}
          sx={{
            display: "block",
            width: "100%",
            height: "auto",
            objectFit: "cover",
            objectPosition: "top center",
            ...(isThumb && {
              height: THUMB_HEIGHT,
              objectFit: "cover",
            }),
            opacity: status === "ready" ? 1 : 0,
            transition: "opacity 120ms ease-in",
          }}
        />
      )}
      {status === "error" && <NoPreviewInline />}
    </Box>
  );
}

function NoPreviewInline() {
  return (
    <Stack direction="row" spacing={0.5} alignItems="center" sx={{ p: 1 }}>
      <AttachEmailRoundedIcon fontSize="small" color="disabled" />
      <Typography variant="caption" color="text.disabled">
        No preview
      </Typography>
    </Stack>
  );
}

function NoPreviewBlock() {
  return (
    <Box
      sx={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 1,
        p: 4,
        borderRadius: 1.5,
        border: 1,
        borderColor: "divider",
        borderStyle: "dashed",
        color: "text.disabled",
      }}
    >
      <AttachEmailRoundedIcon fontSize="large" />
      <Typography variant="body2">No email preview available for this case.</Typography>
    </Box>
  );
}
