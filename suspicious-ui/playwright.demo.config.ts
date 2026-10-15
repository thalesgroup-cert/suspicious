import { defineConfig } from "@playwright/test";

/**
 * Records the product demo video. Not part of `pnpm test:e2e`.
 *   pnpm demo:record   → demo/out/*.webm + .vtt/.srt
 *   pnpm demo:build    → ffmpeg → ../docs/assets/demo/
 */
export default defineConfig({
  testDir: "./demo",
  testMatch: /.*\.demo\.ts/,
  outputDir: "./demo/out/raw",
  fullyParallel: false,
  retries: 0,
  workers: 1,
  timeout: 300_000,
  reporter: [["list"]],

  use: {
    baseURL: "http://localhost:4173",
    viewport: { width: 1280, height: 720 },
    colorScheme: "light",
    locale: "en-GB",
    actionTimeout: 15_000,
    video: { mode: "on", size: { width: 1280, height: 720 } },
    launchOptions: {
      args: ["--force-device-scale-factor=1"],
      // Offline/sandboxed boxes: point at an existing Chromium binary.
      executablePath: process.env.DEMO_CHROMIUM_PATH || undefined,
    },
  },

  projects: [{ name: "chromium", use: { browserName: "chromium" } }],

  // Record against a production build: the dev server (React dev mode + on-demand
  // transforms) is too slow and makes the video stutter.
  webServer: {
    command: "pnpm exec vite build && pnpm exec vite preview --port 4173 --strictPort",
    url: "http://localhost:4173",
    reuseExistingServer: true,
    timeout: 120_000,
  },
});
