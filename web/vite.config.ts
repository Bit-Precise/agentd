import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `pnpm dev` proxies the API to a local agentserver admin listener.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { "/api": process.env.AGENTSERVER_ADMIN_URL || "http://127.0.0.1:7800" },
  },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
