import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  worker: {
    format: "es",
  },
  // No manualChunks: lib/monaco.ts isolates monaco-editor via dynamic import().
  // A manual "monaco" chunk pulled Vite's __vitePreload helper into it and forced a
  // 4.6 MB modulepreload + render-blocking CSS on every boot.
  server: {
    port: 5173,
    proxy: {
      "/v1": {
        target: "http://127.0.0.1:7420",
        changeOrigin: true,
      },
      // Repo-scoped calls for non-default repositories: /r/{name}/v1/...
      "/r/": {
        target: "http://127.0.0.1:7420",
        changeOrigin: true,
      },
      "/health": {
        target: "http://127.0.0.1:7420",
        changeOrigin: true,
      },
      "/.well-known": {
        target: "http://127.0.0.1:7420",
        changeOrigin: true,
      },
    },
  },
});
