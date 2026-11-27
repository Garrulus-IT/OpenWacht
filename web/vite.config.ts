// SPDX-License-Identifier: AGPL-3.0-only

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Die gebaute Oberfläche landet dort, wo die Zentrale sie per go:embed einbindet.
// emptyOutDir ist aus, weil dort eine eingecheckte Platzhalterdatei liegt;
// alte Builds räumt tools/build vorher weg.
export default defineConfig({
  plugins: [react()],
  // Relativ bauen: Der Server setzt den Basis-Pfad in index.html ein (basis.go).
  base: "./",
  build: {
    outDir: "../internal/webui/dist",
    emptyOutDir: false,
    sourcemap: false,
    assetsInlineLimit: 0, // keine data:-URLs, passt zur strikten CSP
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8443" },
  },
});
