#!/usr/bin/env node
// packages/server/src/index.ts
//
// agentarb-server binary: binds the arbiter service.
//
//   AGENTARB_DATA_DIR  data directory (default ./agentarb-data)
//   AGENTARB_HOST      bind host (default 127.0.0.1 — local only)
//   AGENTARB_PORT      bind port (default 3000)
//   AGENTARB_DB        SQLite path (default <dataDir>/agentarb.db;
//                      use :memory: for ephemeral runs)
//   AGENTARB_ALLOW_NOW_OVERRIDE=1  allow adjudicate `now` overrides (tests)
//
// The server owns its AgentCred replay ledger: SI_WALLET_DIR is set to the
// data dir unless already set, so mandate verification consumes jtis in
// the server's ledger, not the operator's ~/.sov-id.

import fs from "node:fs";
import path from "node:path";
import { createApp } from "./app.js";
import { Store } from "./store.js";

function main(): void {
  const dataDir =
    process.env.AGENTARB_DATA_DIR || path.join(process.cwd(), "agentarb-data");
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  // mkdir's mode only applies at creation — tighten a pre-existing dir
  // too, since it holds the arbiter private key. Best effort: a dir the
  // process cannot chmod is left as-is rather than failing startup.
  try {
    fs.chmodSync(dataDir, 0o700);
  } catch {
    // ignore
  }
  if (!process.env.SI_WALLET_DIR) {
    process.env.SI_WALLET_DIR = dataDir;
  }
  const dbPath = process.env.AGENTARB_DB || path.join(dataDir, "agentarb.db");
  const store = new Store(dbPath);
  const app = createApp({
    store,
    allowNowOverride: process.env.AGENTARB_ALLOW_NOW_OVERRIDE === "1",
  });
  const host = process.env.AGENTARB_HOST || "127.0.0.1";
  const port = Number(process.env.AGENTARB_PORT || 3000);
  app.listen({ host, port }, (err, address) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`agentarb-server listening on ${address} (data: ${dataDir})`);
  });
  const shutdown = () => {
    void app.close().then(() => {
      store.close();
      process.exit(0);
    });
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main();
