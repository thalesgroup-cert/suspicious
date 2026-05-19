import { defineConfig, mergeConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";
import viteConfig from "./vite.config";

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      globals: true,
      setupFiles: ["./src/test/setup.ts"],
      include: ["src/**/*.test.{ts,tsx}"],
      exclude: ["e2e/**", "node_modules/**"],
      browser: {
        enabled: true,
        provider: playwright(),
        headless: true,
        screenshotFailures: false,
        instances: [{ browser: "chromium" }],
      },
    },
  })
);
