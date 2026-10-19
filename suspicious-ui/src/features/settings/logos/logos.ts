import chroma from "./chroma-logo.svg";
import elasticsearch from "./elasticsearch-logo.svg";
import misp from "./misp-logo.svg";
import thehive from "./thehive-logo.png";
import watcher from "./watcher-logo.png";

// Bundled, never fetched at runtime, so air-gapped installs work. Provenance and licences: LOGOS.md.
// smtp_notify and ai_narration have no brand mark and are absent on purpose: ConnectorLogo shows a neutral icon.
export const CONNECTOR_LOGOS: Record<string, { src: string; brand: string }> = {
  thehive: { src: thehive, brand: "TheHive" },
  misp: { src: misp, brand: "MISP" },
  chromadb: { src: chroma, brand: "Chroma" },
  watcher: { src: watcher, brand: "Watcher" },
  case_search: { src: elasticsearch, brand: "Elasticsearch" },
};
