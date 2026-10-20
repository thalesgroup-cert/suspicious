import chroma from "./chroma-logo.svg";
import elasticsearch from "./elasticsearch-logo.svg";
import misp from "./misp-logo.svg";
import thehive from "./thehive-logo.png";
import watcher from "./watcher-logo.png";

// Bundled, never fetched at runtime, so air-gapped installs work. Provenance and licences: LOGOS.md.
// smtp_notify and ai_narration have no brand mark and are absent on purpose: ConnectorLogo shows a neutral icon.
// `accent` is the logo's dominant colour, used only as the soft glow behind its tile (a branding exception, recorded in LOGOS.md).
// Connectors without one fall back to the theme primary.
export const CONNECTOR_LOGOS: Record<string, { src: string; brand: string; accent?: string }> = {
  thehive: { src: thehive, brand: "TheHive", accent: "#F0D030" },
  misp: { src: misp, brand: "MISP", accent: "#2FA1DB" },
  chromadb: { src: chroma, brand: "Chroma", accent: "#FF6446" },
  watcher: { src: watcher, brand: "Watcher", accent: "#1F5FA0" },
  case_search: { src: elasticsearch, brand: "Elasticsearch", accent: "#005571" },
};
