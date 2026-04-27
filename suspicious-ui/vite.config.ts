import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src")
    }
  },
  server: {
    host: true,
    port: 5173,
    strictPort: true,
    // Optional local dev convenience:
    // proxy API calls to your backend to avoid CORS in dev.
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true
      }
    }
  },
  build: {
    sourcemap: false,
    outDir: "dist",
    rollupOptions: {
      output: {
        // Split large vendor libraries into stable, long-cacheable chunks.
        // Route pages are automatically split by React.lazy() above.
        manualChunks(id) {
          if (!id.includes("node_modules")) return;

          // React core — present on every page, cached aggressively
          if (
            id.includes("/react/") ||
            id.includes("/react-dom/") ||
            id.includes("react-router")
          ) return "vendor-react";

          // MUI + Emotion — large but stable; isolate from app churn
          if (id.includes("@mui") || id.includes("@emotion"))
            return "vendor-mui";

          // Charting — only loaded on Dashboard / Campaigns
          if (id.includes("recharts") || id.includes("/d3"))
            return "vendor-charts";

          // TanStack Query — used everywhere, worth its own chunk
          if (id.includes("@tanstack")) return "vendor-query";

          // Everything else (axios, zod, notistack, react-hook-form, etc.)
          return "vendor";
        },
      },
    },
  }
});
