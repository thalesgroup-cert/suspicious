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
