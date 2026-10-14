import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  build: {
    // Third-party code changes rarely; keep it in its own files so browsers keep it cached.
    rollupOptions: {
      output: {
        manualChunks: (id) =>
          id.includes("node_modules")
            ? /antd|@ant-design|rc-|@rc-component/.test(id)
              ? "antd"
              : "vendor"
            : undefined,
      },
    },
    chunkSizeWarningLimit: 1200,
  },
  server: {
    proxy: { "/api": { target: "http://127.0.0.1:5080", changeOrigin: false } },
  },
  test: { environment: "jsdom", setupFiles: ["./tests/setup.ts"] },
});
