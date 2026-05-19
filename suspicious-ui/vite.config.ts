import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { boneyardPlugin } from "boneyard-js/vite";
import path from "node:path";

export default defineConfig({
  plugins: [
    react(),
    boneyardPlugin({
      out: "./src/bones",
      framework: "react",
    }),
  ],
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
        manualChunks(id) {
          if (!id.includes("node_modules")) return;
          if (
            id.includes("/react/") ||
            id.includes("/react-dom/") ||
            id.includes("react-router")
          ) return "vendor-react";
          if (id.includes("@mui") || id.includes("@emotion")) return "vendor-mui";
          if (id.includes("recharts") || id.includes("/d3")) return "vendor-charts";
          if (id.includes("@tanstack")) return "vendor-query";
          return "vendor";
        },
      },
    },
  }
});
