#!/usr/bin/env node
// packages/cli/src/index.ts
//
// agentarb CLI: bundle, submit, verify, verdict. Offline verification of
// bundles and verdicts is first-class — no server needed to check a
// signature, a trust tier, or a verdict.
//
// Key files: JSON as printed by `agentarb keygen`
//   { did, privateJwk, publicJwk }
// or a bare Ed25519 private JWK. Key files written by this CLI get mode
// 0600. Treat them like passwords.

import fs from "node:fs";
import path from "node:path";
import {
  addBundleSignature,
  bundleHash,
  evidenceSignPayload,
  generateKeypair,
  signBundle,
  signJws,
  verifyBundle,
  verifyVerdict,
  type Bundle,
  type BundlePayload,
  type Ed25519Jwk,
  type EvidenceItem,
} from "@tamtunnel/agentarb-core";

const VERSION = "0.1.0";

const USAGE = `agentarb ${VERSION} — small-claims court for agent commerce

Usage:
  agentarb keygen [--out <file>]
      Generate an Ed25519 did:key identity. Prints JSON unless --out is
      given (then the file gets mode 0600 and only the DID is printed).

  agentarb bundle sign --key <keyfile> --in <bundle.json> [--out <file>]
      Append a signature to a bundle payload (or an already-signed bundle).

  agentarb bundle verify --in <bundle.json>
      Offline verification: structure, signatures, evidence tiers, hash.

  agentarb verify --in <file.json>
      Auto-detect bundle vs verdict by the format field and verify it.

  agentarb verdict verify --in <verdict.json> [--trusted <did,did,...>]
      Verify a verdict signature (and, when --trusted is given, that the
      arbiter is in the trusted set).

  agentarb submit --server <url> --in <bundle.json>
      Submit a signed bundle to an arbiter server.

  agentarb adjudicate --server <url> --case <case-id> [--now <iso>]
      Ask the server to adjudicate a case (all claims).

  agentarb case --server <url> --id <case-id>
      Fetch a case from the server.

  agentarb demo --scenario <non-delivery|late-delivery|wrong-partial-delivery> --out <dir>
      Generate a complete demo: keys, signed bundle, and the commands to
      submit and adjudicate it.

  agentarb help | agentarb --version
`;

type Args = {
  positional: string[];
  flags: Record<string, string | true>;
};

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const eq = key.indexOf("=");
      if (eq >= 0) {
        flags[key.slice(0, eq)] = key.slice(eq + 1);
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        flags[key] = argv[++i];
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function flag(args: Args, name: string): string | undefined {
  const v = args.flags[name];
  return typeof v === "string" ? v : undefined;
}

function required(args: Args, name: string): string {
  const v = flag(args, name);
  if (v === undefined) {
    console.error(`missing required flag --${name}`);
    process.exitCode = 2;
    throw new Error(`missing --${name}`);
  }
  return v;
}

function readJson(file: string): unknown {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file: string, value: unknown, mode?: number): void {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n");
  if (mode !== undefined) fs.chmodSync(file, mode);
}

function loadPrivateKey(keyfile: string): Ed25519Jwk {
  const data = readJson(keyfile) as Record<string, unknown>;
  if (data.privateJwk) return data.privateJwk as Ed25519Jwk;
  if (data.kty === "OKP" && data.crv === "Ed25519" && data.d) {
    return data as unknown as Ed25519Jwk;
  }
  throw new Error(
    `${keyfile} is not a keygen output or a bare Ed25519 private JWK`,
  );
}

function printBundleReport(bundle: unknown): boolean {
  const v = verifyBundle(bundle);
  if (!v.ok) {
    console.log("INVALID bundle:");
    for (const e of v.errors) console.log(`  - ${e}`);
    return false;
  }
  console.log("VALID bundle");
  console.log(`  hash:    ${v.hash}`);
  console.log(`  signers: ${v.signers.join(", ")}`);
  for (const ev of v.evidence) {
    console.log(`  evidence ${ev.item.id}: tier ${ev.tier} (${ev.tierName})`);
  }
  return true;
}

function printVerdictReport(verdict: unknown, trusted?: string[]): boolean {
  const v = verifyVerdict(
    verdict,
    trusted ? { trustedArbiters: trusted } : {},
  );
  if (!v.ok) {
    console.log("INVALID verdict:");
    for (const e of v.errors) console.log(`  - ${e}`);
    return false;
  }
  const d = verdict as Record<string, unknown>;
  console.log("VALID verdict");
  console.log(`  id:       ${d.id}`);
  console.log(`  method:   ${d.method}`);
  console.log(`  outcome:  ${d.outcome}`);
  console.log(`  refund:   ${d.refund_minor} ${d.currency}`);
  console.log(`  arbiter:  ${d.arbiter}`);
  if (d.ruleset_id) {
    console.log(`  ruleset:  ${d.ruleset_id} v${d.ruleset_version} (${String(d.ruleset_hash).slice(0, 12)}…)`);
  }
  return true;
}

async function postJson(url: string, body: unknown): Promise<{ status: number; json: unknown; text: string }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    // leave as text
  }
  return { status: res.status, json, text };
}

async function getJson(url: string): Promise<{ status: number; json: unknown; text: string }> {
  const res = await fetch(url);
  const text = await res.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    // leave as text
  }
  return { status: res.status, json, text };
}

function isoDaysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const [cmd, sub] = args.positional;

  if (cmd === undefined || cmd === "help" || cmd === "--help") {
    console.log(USAGE);
    return;
  }
  if (cmd === "--version") {
    console.log(VERSION);
    return;
  }

  if (cmd === "keygen") {
    const kp = generateKeypair();
    const out = flag(args, "out");
    if (out) {
      writeJson(out, kp, 0o600);
      console.log(kp.did);
    } else {
      console.log(JSON.stringify(kp, null, 2));
    }
    return;
  }

  if (cmd === "bundle" && sub === "sign") {
    const keyfile = required(args, "key");
    const infile = required(args, "in");
    const bundle = readJson(infile) as Bundle;
    const privateJwk = loadPrivateKey(keyfile);
    let signed: Bundle;
    if (Array.isArray(bundle.signatures) && bundle.signatures.length > 0) {
      signed = addBundleSignature(bundle, privateJwk);
    } else {
      const { signatures: _s, ...payload } = bundle as Bundle & { signatures?: unknown };
      void _s;
      signed = signBundle(payload as BundlePayload, privateJwk);
    }
    const out = flag(args, "out");
    if (out) writeJson(out, signed);
    else console.log(JSON.stringify(signed, null, 2));
    return;
  }

  if (cmd === "bundle" && sub === "verify") {
    const infile = required(args, "in");
    const ok = printBundleReport(readJson(infile));
    process.exitCode = ok ? 0 : 1;
    return;
  }

  if (cmd === "verify") {
    const infile = required(args, "in");
    const doc = readJson(infile) as Record<string, unknown>;
    if (doc.format === "agentarb-bundle") {
      process.exitCode = printBundleReport(doc) ? 0 : 1;
    } else if (doc.format === "agentarb-verdict") {
      process.exitCode = printVerdictReport(doc) ? 0 : 1;
    } else {
      console.error(`unknown format: ${String(doc.format)}`);
      process.exitCode = 2;
    }
    return;
  }

  if (cmd === "verdict" && sub === "verify") {
    const infile = required(args, "in");
    const trusted = flag(args, "trusted");
    const ok = printVerdictReport(
      readJson(infile),
      trusted ? trusted.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
    );
    process.exitCode = ok ? 0 : 1;
    return;
  }

  if (cmd === "submit") {
    const server = required(args, "server").replace(/\/$/, "");
    const infile = required(args, "in");
    const bundle = readJson(infile);
    const { status, json, text } = await postJson(`${server}/v1/cases`, { bundle });
    if (status >= 400) {
      console.error(`submit failed (${status}): ${text}`);
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(json, null, 2));
    return;
  }

  if (cmd === "adjudicate") {
    const server = required(args, "server").replace(/\/$/, "");
    const caseId = required(args, "case");
    const now = flag(args, "now");
    const { status, json, text } = await postJson(
      `${server}/v1/cases/${caseId}/adjudicate`,
      now ? { now } : {},
    );
    if (status >= 400) {
      console.error(`adjudicate failed (${status}): ${text}`);
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(json, null, 2));
    return;
  }

  if (cmd === "case") {
    const server = required(args, "server").replace(/\/$/, "");
    const id = required(args, "id");
    const { status, json, text } = await getJson(`${server}/v1/cases/${id}`);
    if (status >= 400) {
      console.error(`case fetch failed (${status}): ${text}`);
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(json, null, 2));
    return;
  }

  if (cmd === "demo") {
    const scenario = required(args, "scenario");
    const outDir = required(args, "out");
    if (!["non-delivery", "late-delivery", "wrong-partial-delivery"].includes(scenario)) {
      console.error(`unknown scenario: ${scenario}`);
      process.exitCode = 2;
      return;
    }
    fs.mkdirSync(outDir, { recursive: true });
    const claimant = generateKeypair();
    const respondent = generateKeypair();
    const oracle = generateKeypair();
    writeJson(path.join(outDir, "claimant.json"), claimant, 0o600);
    writeJson(path.join(outDir, "respondent.json"), respondent, 0o600);
    writeJson(path.join(outDir, "oracle.json"), oracle, 0o600);

    const evidence: EvidenceItem[] = [];
    let claims: Array<Record<string, unknown>>;
    if (scenario === "non-delivery") {
      claims = [{ type: "non-delivery", amount_minor: 10000, details: {} }];
    } else if (scenario === "late-delivery") {
      claims = [{ type: "late-delivery", amount_minor: 10000, details: { penalty_minor: 1500 } }];
      const bare: EvidenceItem = {
        id: "ev-delivery",
        kind: "delivery-proof",
        content: "Carrier scan: delivered late",
        delivered_at: isoDaysAgo(2),
        submitted_by: claimant.did,
      };
      evidence.push({
        ...bare,
        signer: oracle.did,
        jws: signJws(evidenceSignPayload(bare), oracle.privateJwk),
      });
    } else {
      claims = [{ type: "wrong-partial-delivery", amount_minor: 10000, details: { missing_minor: 3000 } }];
      const bare: EvidenceItem = {
        id: "ev-condition",
        kind: "condition-proof",
        content: "Inspection: 2 of 5 crates missing",
        submitted_by: claimant.did,
      };
      evidence.push({
        ...bare,
        signer: oracle.did,
        jws: signJws(evidenceSignPayload(bare), oracle.privateJwk),
      });
    }
    const payload: BundlePayload = {
      format: "agentarb-bundle",
      version: 1,
      id: `bundle-demo-${scenario}`,
      created_at: new Date().toISOString(),
      claimant: claimant.did,
      respondent: respondent.did,
      transaction: {
        ref: `demo-${scenario}`,
        currency: "USD",
        amount_minor: 10000,
        description: `Demo ${scenario} dispute (fake data)`,
        agreed_delivery_at: isoDaysAgo(5),
      },
      claims: claims as never,
      evidence,
    };
    const bundle = signBundle(payload, claimant.privateJwk);
    const bundlePath = path.join(outDir, "bundle.json");
    writeJson(bundlePath, bundle);
    console.log(`demo bundle: ${bundlePath}`);
    console.log(`bundle hash: ${bundleHash(bundle)}`);
    console.log("");
    console.log("Next steps (server on http://127.0.0.1:3000):");
    console.log(`  agentarb submit --server http://127.0.0.1:3000 --in ${bundlePath}`);
    console.log(`  agentarb adjudicate --server http://127.0.0.1:3000 --case <case-id>`);
    console.log(`  agentarb verify --in ${bundlePath}   # offline check, no server needed`);
    return;
  }

  console.error(`unknown command: ${[cmd, sub].filter(Boolean).join(" ")}\n`);
  console.log(USAGE);
  process.exitCode = 2;
}

main().catch((e) => {
  console.error(`agentarb: ${(e as Error).message}`);
  process.exitCode = 1;
});
