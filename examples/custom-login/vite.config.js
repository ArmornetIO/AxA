// No `defineConfig` import on purpose: a plain object needs nothing from the
// vite package at config time.
import { fileURLToPath } from "node:url";

// The identity client is consumed as raw source — the same alias a real host
// sets (see axa/ts/README.md).
const axa = fileURLToPath(new URL("../../ts/index.ts", import.meta.url));

// The browser only ever sees this dev server's origin, so the session cookie,
// the issuer at /dex and the callback all live on one origin. gin-basic runs
// behind it: BASE_URL=http://localhost:5174 ADDR=:8081.
const backend = "http://localhost:8081";

export default {
  resolve: { alias: { axa } },
  server: {
    port: 5174,
    strictPort: true,
    proxy: {
      "/api": backend,
      "/dex": backend,
    },
  },
};
