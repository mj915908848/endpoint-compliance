import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { "/api": { target: "http://127.0.0.1:5080", changeOrigin: false } },
  },
  test: { environment: "jsdom", setupFiles: ["./tests/setup.ts"] },
});
