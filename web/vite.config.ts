import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));

// `pnpm dev` proxies the API to a local agentserver admin listener.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": resolve(root, "src") } },
  server: {
    proxy: { "/api": process.env.AGENTSERVER_ADMIN_URL || "http://127.0.0.1:7800" },
  },
  test: {
    environment: "jsdom",
  },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
