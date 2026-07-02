import { Box, Typography } from "@mui/material";
import type { ThemeCapabilities } from "@/styles/ThemeStore";

// ThemeGreeting — lore-aware sub-headline, only rendered for themed variants.
export function ThemeGreeting({ caps, name }: { caps: ThemeCapabilities; name: string }) {
  const codename = name.toUpperCase().replace(/\s+/g, "_");

  // ── Le Visiteur du Futur ────────────────────────────────────────────────
  if (caps.effects.hasPortalEffect) {
    return (
      <Box
        className="visitor-briefing"
        sx={{ mt: 0.75, display: "inline-block", fontSize: "11px !important" }}
      >
        {`// TEMPORAL_AGENT: ${codename}`}
      </Box>
    );
  }

  // ── Metal ────────────────────────────────────────────────
  if (caps.effects.hasStealthMode) {
    return (
      <Typography
        variant="caption"
        sx={{
          display: "block",
          mt: 0.5,
          fontFamily: '"IBM Plex Mono", monospace',
          letterSpacing: "0.08em",
          color: "var(--mgs-codec, #37D6C7)",
          opacity: 0.85,
        }}
      >
        {`CODEC :: CH ${caps.cssVars.includes("--mgs-codec-snake") ? "140.85" : "???"}  ▸  AGENT: ${codename}`}
      </Typography>
    );
  }

  // ── Cyber / matrix ──────────────────────────────────────────────────────
  if (caps.effects.hasNeonEffect) {
    return (
      <Typography
        variant="caption"
        sx={{
          display: "block",
          mt: 0.5,
          fontFamily: '"IBM Plex Mono", monospace',
          letterSpacing: "0.1em",
          color: "#00E5FF",
          textShadow: "0 0 8px rgba(0,229,255,.5)",
          opacity: 0.88,
        }}
      >
        {`SYS: ACCESS_GRANTED  //  USER: ${codename}  //  THREAT_MATRIX: ONLINE`}
      </Typography>
    );
  }

  // ── Seasonal ────────────────────────────────────────────────────────────
  const seasonLine: Record<string, string> = {
    spring: "Spring cycle underway — threats don't take the season off.",
    summer: "Peak season. Stay cool, stay vigilant.",
    autumn: "Autumn watch — threat embers persist.",
    winter: "Festive season — peak phishing window. Watch your inbox.",
  };
  if (caps.season && seasonLine[caps.season]) {
    return (
      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
        {seasonLine[caps.season]}
      </Typography>
    );
  }

  return null;
}
