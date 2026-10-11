import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const target = process.env.VITE_PROXY_TARGET ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: { host: true, port: 5173, proxy: { "/api": { target, changeOrigin: true } } },
  test: { environment: "node" },
});
