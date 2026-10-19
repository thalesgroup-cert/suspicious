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
          // three.js and react-three-fiber/drei are only reached from the lazy 3D map on /campaigns.
          // Left out of the shared "vendor" chunk, which the entry loads on every page, the bundler
          // keeps them in the chunk(s) that import() pulls in.
          if (/[\\/]node_modules[\\/](three|three-stdlib|@react-three|react-reconciler|its-fine|suspend-react|react-use-measure|debounce|meshline|maath|camera-controls|stats-gl|stats\.js|detect-gpu|hls\.js|@monogrid|three-mesh-bvh|troika-[^\\/]+|bidi-js|webgl-sdf-generator|potpack|fflate|draco3d|zustand-traditional)[\\/]/.test(id)) return;
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
