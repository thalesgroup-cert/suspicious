import { describe, expect, it } from "vitest";

import { CONNECTOR_LOGOS } from "../../logos/logos";
import provenance from "../../logos/LOGOS.md?raw";

// Browser mode has no fs: Vite's glob lists the folder at build time and
// `?url` gives the same URLs the asset imports in logos.ts resolve to.
const files = import.meta.glob("../../logos/*.{svg,png}", { query: "?url", import: "default", eager: true }) as Record<string, string>;

describe("bundled connector logos", () => {
  it("maps the five branded connectors", () => {
    expect(Object.keys(CONNECTOR_LOGOS).sort()).toEqual(["case_search", "chromadb", "misp", "thehive", "watcher"]);
    for (const l of Object.values(CONNECTOR_LOGOS)) expect(l.brand).toBeTruthy();
  });

  it("points every mapping at a file that exists in the logos folder", () => {
    const urls = new Set(Object.values(files));
    for (const [name, l] of Object.entries(CONNECTOR_LOGOS)) expect(urls.has(l.src), name).toBe(true);
  });

  it("lists every logo file in LOGOS.md with source, licence and date columns", () => {
    expect(Object.keys(files).length).toBeGreaterThanOrEqual(5);
    for (const path of Object.keys(files)) expect(provenance, path).toContain(path.split("/").pop()!);
    expect(provenance).toMatch(/\| File \| Brand \| Source URL \| Licence \| Retrieved \| Modification \|/);
  });

  it("keeps every file at most 20 kB", async () => {
    for (const url of Object.values(files)) {
      const buf = await (await fetch(url)).arrayBuffer();
      expect(buf.byteLength, url).toBeLessThanOrEqual(20 * 1024);
    }
  });

  it("has no scripts or external references in the SVGs", async () => {
    for (const [path, url] of Object.entries(files).filter(([p]) => p.endsWith(".svg"))) {
      const text = await (await fetch(url)).text();
      expect(text, path).not.toMatch(/<script|href=["']https?:|on\w+=|<image|<metadata/i);
      expect(text, path).toMatch(/viewBox=/);
    }
  });
});
