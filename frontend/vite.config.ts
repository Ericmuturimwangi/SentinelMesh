import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Dev server talks to the Flask app on the same origin so the session
    // cookie behaves exactly as it does in production.
    proxy: {
      "/api": "http://127.0.0.1:8099",
      "/soc": "http://127.0.0.1:8099",
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: true,
  },
});
