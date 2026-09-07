import { defineConfig, mergeConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";
import viteConfig from "./vite.config";

export default mergeConfig(
  viteConfig,
  defineConfig({
    // Pre-bundle the shared test dependencies up front. Otherwise a suite
    // can be the first to import e.g. @testing-library/react mid-run, which
    // triggers a full Vite re-optimize and invalidates the dep URLs other
    // parallel browser suites are still fetching — surfacing as
    // "Failed to fetch dynamically imported module .../@testing-library_react.js".
    optimizeDeps: {
      include: [
        "@testing-library/react",
        "@testing-library/dom",
        "@testing-library/user-event",
        "@testing-library/jest-dom",
        "react",
        "react-dom",
        "react-dom/client",
        "react/jsx-dev-runtime",
        "axios",
        "react-joyride",
        "@mui/icons-material/BlockOutlined",
        "@mui/icons-material/CheckCircleOutlined",
        "@mui/icons-material/EmailOutlined",
        "@mui/icons-material/ExtensionOutlined",
        "@mui/icons-material/HubOutlined",
        "@mui/icons-material/ShareOutlined",
        "@mui/icons-material/VisibilityOutlined",
        "@mui/icons-material/WarningAmberOutlined",
      ],
    },
    test: {
      globals: true,
      setupFiles: ["./src/test/setup.ts"],
      include: ["src/**/*.test.{ts,tsx}"],
      exclude: ["e2e/**", "node_modules/**"],
      // Parallel file execution in browser mode shares module/dep state
      // across the concurrently-running suites (same class of issue as the
      // optimizeDeps race above), which has surfaced as spurious CI failures
      // in unrelated files — a vi.mock'd module resolving to its real,
      // unmocked implementation (api.test.ts: "vi.mocked(...).mockResolvedValue
      // is not a function") or an unrelated assertion failing outright
      // (ProfilePage.test.tsx). Serializing file execution has been 100%
      // reliable locally across many runs (and finishes in under a minute for
      // this suite size) vs. an intermittent per-file flake under parallelism.
      fileParallelism: false,
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
