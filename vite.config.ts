import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Overridable so a second instance can run alongside the first
// (`pnpm start -p 3110` — see scripts/start.mjs). Defaults match the single
// instance everything else documents: UI on 3100, API on 8787.
const port = Number(process.env.PORT ?? 3100);
const apiTarget = process.env.API_PROXY_TARGET ?? "http://127.0.0.1:8787";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    host: "127.0.0.1",
    port,
    strictPort: true,
    proxy: {
      "/api": {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
  // The preview server inherits server.proxy, so /api keeps working after a
  // production build too.
  preview: {
    host: "127.0.0.1",
    port,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    target: "esnext",
  },
})
