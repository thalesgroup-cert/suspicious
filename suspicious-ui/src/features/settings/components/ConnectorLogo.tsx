import { useState } from "react";
import AutoAwesomeOutlined from "@mui/icons-material/AutoAwesomeOutlined";
import { Box } from "@mui/material";

import { CONNECTOR_LOGOS } from "../logos/logos";
import { CONNECTOR_ICONS, DEFAULT_CONNECTOR_ICON } from "./connectorIcons";

// ai_narration has no single brand (Ollama, OpenAI, Anthropic, Gemini), so it gets a neutral sparkle instead of the generic puzzle piece.
const FALLBACK_ICONS = { ...CONNECTOR_ICONS, ai_narration: AutoAwesomeOutlined };

/**
 * Fixed square tile. A bundled logo sits on white in every theme (brand marks are drawn for light
 * backgrounds, e.g. MISP's grey wordmark or a dark Elasticsearch mark); the neutral icon fallback sits on the paper surface.
 * Decorative (alt ""): the connector name is always printed beside it. Never recoloured.
 */
export function ConnectorLogo({ name, size = 40 }: { name: string; size?: number }) {
  const logo = CONNECTOR_LOGOS[name];
  // Keyed by name so a tile reused for another connector does not stay on the fallback.
  const [failedFor, setFailedFor] = useState<string | null>(null);
  const failed = failedFor === name;
  const Icon = FALLBACK_ICONS[name as keyof typeof FALLBACK_ICONS] ?? DEFAULT_CONNECTOR_ICON;
  return (
    <Box
      data-testid="connector-logo"
      sx={{
        width: size,
        height: size,
        boxSizing: "border-box",
        flexShrink: 0,
        display: "grid",
        placeItems: "center",
        p: `${Math.round(size * 0.15)}px`,
        bgcolor: logo && !failed ? "common.white" : "background.paper",
        border: 1,
        borderColor: "divider",
        borderRadius: 1,
        overflow: "hidden",
      }}
    >
      {logo && !failed ? (
        <Box
          component="img"
          src={logo.src}
          alt=""
          onError={() => setFailedFor(name)}
          sx={{ width: "100%", height: "100%", objectFit: "contain", display: "block" }}
        />
      ) : (
        <Icon sx={{ fontSize: Math.round(size * 0.55), color: "text.secondary" }} />
      )}
    </Box>
  );
}
