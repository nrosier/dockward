import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import pkg from "./package.json" with { type: "json" };

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The backend replaces this placeholder with a fresh nonce on every HTML
  // response (specs/security.md, "Security headers").
  html: { cspNonce: "HG_CSP_NONCE" },
  build: {
    // No `data:` URIs: the CSP blocks them.
    assetsInlineLimit: 0,
  },
  define: {
    APP_VERSION: JSON.stringify(pkg.version),
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test/setup.ts"],
  },
});
