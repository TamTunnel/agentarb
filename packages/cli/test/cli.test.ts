import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateKeypair,
  signRevocation,
  signVerdict,
  verdictIdFor,
  verdictSignPayload,
  type Verdict,
  type VerdictCore,
} from "@tamtunnel/agentarb-core";

const here = path.dirname(fileURLToPath(import.meta.url));
const cliPath = path.join(here, "..", "dist", "index.js");
const serverPath = path.join(
  here,
  "..",
  "..",
  "server",
  "dist",
  "index.js",
);

function runCli(args: string[], cwd: string): { code: number; out: string } {
  try {
    const out = execFileSync(process.execPath, [cliPath, ...args], {
      cwd,
      encoding: "utf8",
    });
    return { code: 0, out };
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return {
      code: err.status ?? 1,
      out: (err.stdout ?? "") + (err.stderr ?? ""),
    };
  }
}

function tmpdir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "agentarb-cli-test-"));
}

test("cli: keygen prints a usable identity", () => {
  const dir = tmpdir();
  const { code, out } = runCli(["keygen"], dir);
  assert.equal(code, 0, out);
  const kp = JSON.parse(out);
  assert.ok(kp.did.startsWith("did:key:z"));
  assert.equal(kp.privateJwk.kty, "OKP");
  assert.equal(kp.privateJwk.crv, "Ed25519");
});

test("cli: keygen --out writes mode 0600", () => {
  const dir = tmpdir();
  const keyfile = path.join(dir, "key.json");
  const { code, out } = runCli(["keygen", "--out", keyfile], dir);
  assert.equal(code, 0, out);
  assert.ok(out.trim().startsWith("did:key:z"));
  assert.equal(fs.statSync(keyfile).mode & 0o777, 0o600);
});

test("cli: demo bundle verifies offline, tampering fails", () => {
  const dir = tmpdir();
  const demoDir = path.join(dir, "demo");
  const demo = runCli(
    ["demo", "--scenario", "late-delivery", "--out", demoDir],
    dir,
  );
  assert.equal(demo.code, 0, demo.out);
  const bundlePath = path.join(demoDir, "bundle.json");
  const ok = runCli(["verify", "--in", bundlePath], dir);
  assert.equal(ok.code, 0, ok.out);
  assert.match(ok.out, /VALID bundle/);
  assert.match(ok.out, /tier 2/);
  const tampered = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  tampered.transaction.amount_minor = 99999;
  const tamperedPath = path.join(dir, "tampered.json");
  fs.writeFileSync(tamperedPath, JSON.stringify(tampered));
  const bad = runCli(["verify", "--in", tamperedPath], dir);
  assert.equal(bad.code, 1);
  assert.match(bad.out, /INVALID/);
});

test("cli: bundle sign appends a second signer", () => {
  const dir = tmpdir();
  const demoDir = path.join(dir, "demo");
  assert.equal(
    runCli(["demo", "--scenario", "non-delivery", "--out", demoDir], dir).code,
    0,
  );
  const bundlePath = path.join(demoDir, "bundle.json");
  const signedPath = path.join(dir, "signed.json");
  const res = runCli(
    [
      "bundle",
      "sign",
      "--key",
      path.join(demoDir, "respondent.json"),
      "--in",
      bundlePath,
      "--out",
      signedPath,
    ],
    dir,
  );
  assert.equal(res.code, 0, res.out);
  const verify = runCli(["bundle", "verify", "--in", signedPath], dir);
  assert.equal(verify.code, 0, verify.out);
  const signerLines = verify.out.split("\n").find((l) => l.includes("signers:"));
  assert.ok(signerLines);
  assert.equal(signerLines.split(",").length, 2);
});

test("cli: verdict verify accepts trusted arbiter, rejects others", () => {
  const dir = tmpdir();
  const arbiter = generateKeypair();
  const other = generateKeypair();
  const core: VerdictCore = {
    format: "agentarb-verdict",
    version: 1,
    case_id: "case-1",
    bundle_id: "bundle-1",
    bundle_hash: "d".repeat(64),
    ruleset_id: "builtin/non-delivery",
    ruleset_version: 1,
    ruleset_hash: "e".repeat(64),
    method: "rules",
    outcome: "refund_full",
    refund_minor: 10000,
    currency: "USD",
    claim_amount_minor: 10000,
    reasoning: [{ rule: "r", matched: true, reason: "ok" }],
    decided_at: "2026-10-10T00:00:00Z",
    arbiter: arbiter.did,
  };
  const verdict: Verdict = signVerdict(
    { ...core, id: verdictIdFor(verdictSignPayload(core)), signature: null },
    arbiter.privateJwk,
  );
  const verdictPath = path.join(dir, "verdict.json");
  fs.writeFileSync(verdictPath, JSON.stringify(verdict, null, 2));
  const ok = runCli(
    ["verdict", "verify", "--in", verdictPath, "--trusted", arbiter.did],
    dir,
  );
  assert.equal(ok.code, 0, ok.out);
  assert.match(ok.out, /VALID verdict/);
  const bad = runCli(
    ["verdict", "verify", "--in", verdictPath, "--trusted", other.did],
    dir,
  );
  assert.equal(bad.code, 1);
  assert.match(bad.out, /INVALID/);
});

test("cli: submit + adjudicate + case against a live server", async () => {
  const dir = tmpdir();
  const dataDir = path.join(dir, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const port = 34931;
  const server: ChildProcess = spawn(process.execPath, [serverPath], {
    env: {
      ...process.env,
      AGENTARB_DATA_DIR: dataDir,
      AGENTARB_DB: ":memory:",
      AGENTARB_PORT: String(port),
      AGENTARB_ALLOW_NOW_OVERRIDE: "1",
      SI_WALLET_DIR: dataDir,
    },
    stdio: "ignore",
  });
  try {
    const base = `http://127.0.0.1:${port}`;
    // Wait for health (up to ~10s).
    let healthy = false;
    for (let i = 0; i < 50 && !healthy; i++) {
      try {
        const res = await fetch(`${base}/health`);
        healthy = res.ok;
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    assert.equal(healthy, true, "server did not become healthy");

    const demoDir = path.join(dir, "demo");
    assert.equal(
      runCli(["demo", "--scenario", "non-delivery", "--out", demoDir], dir).code,
      0,
    );
    const submitted = runCli(
      ["submit", "--server", base, "--in", path.join(demoDir, "bundle.json")],
      dir,
    );
    assert.equal(submitted.code, 0, submitted.out);
    const caseId = (JSON.parse(submitted.out) as { case_id: string }).case_id;
    const adj = runCli(
      ["adjudicate", "--server", base, "--case", caseId],
      dir,
    );
    assert.equal(adj.code, 0, adj.out);
    const adjBody = JSON.parse(adj.out) as {
      verdicts: Array<{ outcome: string; refund_minor: number }>;
    };
    assert.equal(adjBody.verdicts[0].outcome, "refund_full");
    const fetched = runCli(["case", "--server", base, "--id", caseId], dir);
    assert.equal(fetched.code, 0, fetched.out);
    assert.equal(
      (JSON.parse(fetched.out) as { status: string }).status,
      "adjudicated",
    );
  } finally {
    server.kill();
  }
});

test("cli: verdict verify without --trusted prints the no-trust-set caveat", () => {
  const dir = tmpdir();
  const arbiter = generateKeypair();
  const core: VerdictCore = {
    format: "agentarb-verdict",
    version: 1,
    case_id: "case-1",
    bundle_id: "bundle-1",
    bundle_hash: "d".repeat(64),
    ruleset_id: "builtin/non-delivery",
    ruleset_version: 1,
    ruleset_hash: "e".repeat(64),
    method: "rules",
    outcome: "refund_full",
    refund_minor: 10000,
    currency: "USD",
    claim_amount_minor: 10000,
    reasoning: [{ rule: "r", matched: true, reason: "ok" }],
    decided_at: "2026-10-10T00:00:00Z",
    arbiter: arbiter.did,
  };
  const verdict: Verdict = signVerdict(
    { ...core, id: verdictIdFor(verdictSignPayload(core)), signature: null },
    arbiter.privateJwk,
  );
  const verdictPath = path.join(dir, "verdict.json");
  fs.writeFileSync(verdictPath, JSON.stringify(verdict, null, 2));
  const res = runCli(["verdict", "verify", "--in", verdictPath], dir);
  assert.equal(res.code, 0, res.out);
  assert.match(res.out, /VALID verdict/);
  assert.match(res.out, /no --trusted set given/);
});

test("cli: verdict verify --revocations flags a revoked verdict, passes others", () => {
  const dir = tmpdir();
  const arbiter = generateKeypair();
  const core: VerdictCore = {
    format: "agentarb-verdict",
    version: 1,
    case_id: "case-1",
    bundle_id: "bundle-1",
    bundle_hash: "d".repeat(64),
    ruleset_id: "builtin/non-delivery",
    ruleset_version: 1,
    ruleset_hash: "e".repeat(64),
    method: "rules",
    outcome: "refund_full",
    refund_minor: 10000,
    currency: "USD",
    claim_amount_minor: 10000,
    reasoning: [{ rule: "r", matched: true, reason: "ok" }],
    decided_at: "2026-10-10T00:00:00Z",
    arbiter: arbiter.did,
  };
  const verdict: Verdict = signVerdict(
    { ...core, id: verdictIdFor(verdictSignPayload(core)), signature: null },
    arbiter.privateJwk,
  );
  const verdictPath = path.join(dir, "verdict.json");
  fs.writeFileSync(verdictPath, JSON.stringify(verdict, null, 2));
  // Without --revocations, a revoked verdict still reads VALID (crypto
  // only) — but the caveat note must be present.
  const entry = signRevocation(
    {
      verdict_id: verdict.id,
      reason: "issued in error",
      revoked_at: "2026-10-11T00:00:00Z",
      arbiter: arbiter.did,
    },
    arbiter.privateJwk,
  );
  const revPath = path.join(dir, "revocations.json");
  fs.writeFileSync(revPath, JSON.stringify([entry], null, 2));
  const plain = runCli(["verdict", "verify", "--in", verdictPath], dir);
  assert.equal(plain.code, 0, plain.out);
  assert.match(plain.out, /VALID verdict/);
  assert.match(plain.out, /revocation not checked/);
  const flagged = runCli(
    ["verdict", "verify", "--in", verdictPath, "--revocations", revPath],
    dir,
  );
  assert.equal(flagged.code, 1);
  assert.match(flagged.out, /REVOKED verdict/);
  assert.match(flagged.out, /issued in error/);
  // An empty revocation list leaves the verdict VALID.
  const emptyPath = path.join(dir, "empty.json");
  fs.writeFileSync(emptyPath, "[]");
  const clean = runCli(
    ["verdict", "verify", "--in", verdictPath, "--revocations", emptyPath],
    dir,
  );
  assert.equal(clean.code, 0, clean.out);
  assert.match(clean.out, /VALID verdict/);
});
