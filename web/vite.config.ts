import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves the site at https://jacobrhess.github.io/detlab/, so all
// assets need a /detlab/ prefix. Override with VITE_BASE for custom domains.

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    base: env.VITE_BASE ?? "/detlab/",
    plugins: [react()],
    build: {
      outDir: "dist",
      sourcemap: true,
      target: "es2022",
    },
    server: {
      port: 5173,
      open: true,
    },
  };
});
