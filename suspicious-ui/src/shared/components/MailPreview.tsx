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
 * The image is not fetched until the user clicks "Load preview" — every row
 * on a list page mounting its own eager <img> was the actual cost, not the
 * render itself. Once clicked, a skeleton shows while it loads. On a 404
 * (the backend enqueues a background (re)render and 404s on a cache miss),
 * we retry a few times with a cache-busting query param so the freshly
 * rendered PNG is picked up without a manual reload; after `maxRetries` we
 * fall back to a subtle "No preview" hint instead of a broken image icon.
 */
import { useEffect, useRef, useState } from "react";
import { Box, Skeleton, Typography, Stack, IconButton, Button, Tooltip } from "@mui/material";
import AttachEmailRoundedIcon from "@mui/icons-material/AttachEmailRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";

export type MailPreviewProps = {
  /** Relative URL from the API, e.g. "/api/cases/42/mail-preview.png". `null`/empty = no preview. */
  url?: string | null;
  /** Visual size. Defaults to "thumbnail". */
  variant?: "thumbnail" | "full";
  /** Override label shown next to the icon (accessibility). */
  alt?: string;
  /** How many times to retry a failed load before showing "No preview". 0 disables retry. */
  maxRetries?: number;
  /** Delay between retries, ms. */
  retryDelayMs?: number;
};

const THUMB_WIDTH = 96;
const THUMB_HEIGHT = 124;

export default function MailPreview({
  url,
  variant = "thumbnail",
  alt,
  maxRetries = 3,
  retryDelayMs = 4000,
}: MailPreviewProps) {
  const [status, setStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [attempt, setAttempt] = useState(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    },
    [],
  );

  if (!url) {
    return variant === "full" ? <NoPreviewBlock /> : null;
  }

  const isThumb = variant === "thumbnail";

  const handleError = () => {
    if (attempt < maxRetries) {
      timerRef.current = setTimeout(() => {
        setAttempt((n) => n + 1);
        setStatus("loading");
      }, retryDelayMs);
    } else {
      setStatus("error");
    }
  };

  const src = attempt > 0 ? `${url}${url.includes("?") ? "&" : "?"}r=${attempt}` : url;

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
      {status === "idle" && (
        <Box
          sx={{
            width: "100%",
            height: isThumb ? THUMB_HEIGHT : 200,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            bgcolor: "action.hover",
          }}
        >
          {isThumb ? (
            <Tooltip title="Load preview">
              <IconButton size="small" onClick={() => setStatus("loading")} aria-label="Load preview">
                <VisibilityRoundedIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          ) : (
            <Button
              size="small"
              startIcon={<VisibilityRoundedIcon />}
              onClick={() => setStatus("loading")}
            >
              Load preview
            </Button>
          )}
        </Box>
      )}
      {status === "loading" && (
        <Skeleton
          variant="rectangular"
          width="100%"
          height={isThumb ? THUMB_HEIGHT : 320}
          sx={{ position: "absolute", inset: 0 }}
        />
      )}
      {(status === "loading" || status === "ready") && (
        <Box
          component="img"
          key={attempt}
          src={src}
          alt={alt ?? "Email preview"}
          onLoad={() => setStatus("ready")}
          onError={handleError}
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
    <Stack direction="row" spacing={0.5} sx={{ p: 1, alignItems: "center" }}>
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
