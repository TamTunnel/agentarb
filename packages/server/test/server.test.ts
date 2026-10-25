import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  issueGrant,
  mintMandate,
  onboard,
} from "@tamtunnel/si-wallet-core";
import {
  generateKeypair,
  keypairFromSeed,
  signBundle,
  signJws,
  addBundleSignature,
  evidenceSignPayload,
  signVerdict,
  verifyVerdict,
  type Bundle,
  type Keypair,
} from "@tamtunnel/agentarb-core";
import { createApp } from "../dist/app.js";
import { Store } from "../dist/store.js";

// The server verifies mandates against its own replay ledger, and the
// si-wallet-core keystore is encrypted — both use test-only throwaway
// values here, never real credentials.
process.env.SI_WALLET_DIR = fs.mkdtempSync(
  path.join(os.tmpdir(), "agentarb-server-test-"),
);
process.env.SI_WALLET_PASSPHRASE = "agentarb-test-passphrase-only";

const claimant = keypairFromSeed(Buffer.alloc(32, 1));
const respondent = keypairFromSeed(Buffer.alloc(32, 2));
const oracle = keypairFromSeed(Buffer.alloc(32, 3));
const human = generateKeypair();

function makeApp() {
  const store = new Store(":memory:");
  const app = createApp({ store, allowNowOverride: true });
  return { app, store };
}

async function ready(app: ReturnType<typeof createApp>) {
  await app.ready();
  return app;
}

function bundlePayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    format: "agentarb-bundle",
    version: 1,
    id: "bundle-1",
    created_at: "2026-10-20T00:00:00Z",
    claimant: claimant.did,
    respondent: respondent.did,
    transaction: {
      ref: "tx-1",
      currency: "USD",
      amount_minor: 10000,
      description: "Example agent task",
      agreed_delivery_at: "2026-10-01T00:00:00Z",
    },
    claims: [{ type: "non-delivery", amount_minor: 10000, details: {} }],
    evidence: [],
    ...overrides,
  };
}

function signedMulti(payload: Record<string, unknown>, signers: Keypair[]): Bundle {
  let b = signBundle(payload as never, signers[0].privateJwk);
  for (const kp of signers.slice(1)) {
    b = addBundleSignature(b, kp.privateJwk);
  }
  return b;
}

async function submitCase(app: ReturnType<typeof createApp>, bundle: Bundle) {
  const res = await app.inject({
    method: "POST",
    url: "/v1/cases",
    payload: { bundle },
  });
  return { status: res.statusCode, body: res.json() as Record<string, unknown> };
}

test("server: health and empty viewer", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const health = await app.inject({ method: "GET", url: "/health" });
    assert.equal(health.statusCode, 200);
    assert.deepEqual(health.json(), { ok: true });
    const viewer = await app.inject({ method: "GET", url: "/" });
    assert.equal(viewer.statusCode, 200);
    assert.match(viewer.body, /AgentArb cases/);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: submit valid bundle, list, and detail", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { status, body } = await submitCase(app, bundle);
    assert.equal(status, 201, JSON.stringify(body));
    const caseId = body.case_id as string;
    const list = await app.inject({ method: "GET", url: "/v1/cases" });
    assert.equal(list.statusCode, 200);
    assert.equal((list.json() as { cases: unknown[] }).cases.length, 1);
    const detail = await app.inject({ method: "GET", url: `/v1/cases/${caseId}` });
    assert.equal(detail.statusCode, 200);
    assert.equal((detail.json() as { status: string }).status, "open");
  } finally {
    await app.close();
    store.close();
  }
});

test("server: invalid bundle rejected, duplicate bundle id conflicts", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const tampered = { ...bundle, id: "bundle-2" };
    const badRes = await submitCase(app, tampered);
    assert.equal(badRes.status, 400);
    const ok = await submitCase(app, bundle);
    assert.equal(ok.status, 201);
    const dup = await submitCase(app, bundle);
    assert.equal(dup.status, 409);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: add evidence with tier, reject bad signature and duplicates", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const bare = {
      id: "ev-1",
      kind: "delivery-proof",
      content: "carrier scan",
      submitted_by: claimant.did,
    };
    const item = {
      ...bare,
      signer: oracle.did,
      jws: signJws(evidenceSignPayload({ ...bare, signer: null, jws: null } as never), oracle.privateJwk),
    };
    const added = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/evidence`,
      payload: { evidence: item },
    });
    assert.equal(added.statusCode, 201, added.body);
    assert.equal((added.json() as { tier: number }).tier, 2);
    const dup = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/evidence`,
      payload: { evidence: item },
    });
    assert.equal(dup.statusCode, 409);
    const forged = { ...item, id: "ev-2", content: "forged" };
    const badSig = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/evidence`,
      payload: { evidence: forged },
    });
    assert.equal(badSig.statusCode, 400);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: adjudicate non-delivery refunds in full, verdict verifies", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal(adj.statusCode, 200, adj.body);
    const adjBody = adj.json() as { status: string; verdicts: Array<Record<string, unknown>> };
    assert.equal(adjBody.status, "adjudicated");
    assert.equal(adjBody.verdicts[0].outcome, "refund_full");
    assert.equal(adjBody.verdicts[0].refund_minor, 10000);
    const keys = (await app.inject({ method: "GET", url: "/v1/keys" })).json() as {
      active: string;
      retired: string[];
    };
    const v = verifyVerdict(adjBody.verdicts[0], {
      trustedArbiters: [keys.active, ...keys.retired],
    });
    assert.equal(v.ok, true, v.errors.join("; "));
    const viewer = await app.inject({ method: "GET", url: `/cases/${caseId}` });
    assert.equal(viewer.statusCode, 200);
    assert.match(viewer.body, /refund_full/);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: escrow hold is refunded by the verdict", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const hold = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId, claim_index: 0, amount_minor: 10000, currency: "USD" },
    });
    assert.equal(hold.statusCode, 201, hold.body);
    const holdId = (hold.json() as { hold_id: string }).hold_id;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal(adj.statusCode, 200, adj.body);
    const escrow = (adj.json() as { escrow: Array<Record<string, unknown>> }).escrow;
    assert.equal(escrow.length, 1);
    assert.equal(escrow[0].kind, "refund");
    assert.equal(escrow[0].amount_minor, 10000);
    const holdAfter = await app.inject({ method: "GET", url: `/v1/holds/${holdId}` });
    const holdBody = holdAfter.json() as { status: string; remaining_minor: number };
    assert.equal(holdBody.status, "refunded");
    assert.equal(holdBody.remaining_minor, 0);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: reject verdict releases the hold", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bare = {
      id: "ev-delivery",
      kind: "delivery-proof",
      content: "carrier scan",
      delivered_at: "2026-09-30T00:00:00Z",
      submitted_by: claimant.did,
    };
    const proof = {
      ...bare,
      signer: oracle.did,
      jws: signJws(evidenceSignPayload({ ...bare, signer: null, jws: null } as never), oracle.privateJwk),
    };
    const payload = bundlePayload({
      claims: [{ type: "late-delivery", amount_minor: 10000, details: { penalty_minor: 1500 } }],
      evidence: [proof],
    });
    const bundle = signedMulti(payload, [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const hold = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId, claim_index: 0, amount_minor: 10000, currency: "USD" },
    });
    const holdId = (hold.json() as { hold_id: string }).hold_id;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    const adjBody = adj.json() as { verdicts: Array<Record<string, unknown>>; escrow: Array<Record<string, unknown>> };
    assert.equal(adjBody.verdicts[0].outcome, "reject");
    assert.equal(adjBody.escrow[0].kind, "release");
    const holdAfter = (await app.inject({ method: "GET", url: `/v1/holds/${holdId}` })).json() as {
      status: string;
    };
    assert.equal(holdAfter.status, "released");
  } finally {
    await app.close();
    store.close();
  }
});

test("server: escalation then human verdict resolves", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    // Weak-only delivery proof -> rules escalate.
    const bare = {
      id: "ev-delivery",
      kind: "delivery-proof",
      content: "I delivered it",
      submitted_by: respondent.did,
    };
    const proof = {
      ...bare,
      signer: respondent.did,
      jws: signJws(evidenceSignPayload({ ...bare, signer: null, jws: null } as never), respondent.privateJwk),
    };
    const bundle = signedMulti(bundlePayload({ evidence: [proof] }), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal((adj.json() as { status: string }).status, "escalated");
    // Human verdict: refund half, signed by the human reviewer.
    const humanVerdict = signVerdict(
      {
        format: "agentarb-verdict",
        version: 1,
        id: "v_human_1",
        case_id: caseId,
        bundle_id: "bundle-1",
        bundle_hash: "c".repeat(64),
        method: "human",
        outcome: "refund_partial",
        refund_minor: 5000,
        currency: "USD",
        claim_amount_minor: 10000,
        reasoning: [{ rule: "human-review", matched: true, reason: "Split the difference." }],
        decided_at: "2026-10-11T00:00:00Z",
        arbiter: human.did,
        signature: null,
      },
      human.privateJwk,
    );
    const hv = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/human-verdict`,
      payload: { verdict: humanVerdict, claim_index: 0 },
    });
    assert.equal(hv.statusCode, 200, hv.body);
    assert.equal((hv.json() as { status: string }).status, "resolved");
    const detail = (await app.inject({ method: "GET", url: `/v1/cases/${caseId}` })).json() as {
      status: string;
    };
    assert.equal(detail.status, "resolved");
  } finally {
    await app.close();
    store.close();
  }
});

test("server: human verdict on a non-escalated case is rejected", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const humanVerdict = signVerdict(
      {
        format: "agentarb-verdict",
        version: 1,
        id: "v_human_2",
        case_id: caseId,
        bundle_id: "bundle-1",
        bundle_hash: "c".repeat(64),
        method: "human",
        outcome: "reject",
        refund_minor: 0,
        currency: "USD",
        claim_amount_minor: 10000,
        reasoning: [{ rule: "human-review", matched: true, reason: "No." }],
        decided_at: "2026-10-11T00:00:00Z",
        arbiter: human.did,
        signature: null,
      },
      human.privateJwk,
    );
    const hv = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/human-verdict`,
      payload: { verdict: humanVerdict, claim_index: 0 },
    });
    assert.equal(hv.statusCode, 409);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: revoke marks the verdict, double revoke conflicts", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    const verdictId = (adj.json() as { verdicts: Array<{ id: string }> }).verdicts[0].id;
    const rev = await app.inject({
      method: "POST",
      url: `/v1/verdicts/${verdictId}/revoke`,
      payload: { reason: "issued in error" },
    });
    assert.equal(rev.statusCode, 200, rev.body);
    const dup = await app.inject({
      method: "POST",
      url: `/v1/verdicts/${verdictId}/revoke`,
      payload: { reason: "again" },
    });
    assert.equal(dup.statusCode, 409);
    const verdicts = (await app.inject({ method: "GET", url: `/v1/cases/${caseId}/verdicts` })).json() as {
      verdicts: Array<{ revoked: unknown }>;
    };
    assert.notEqual(verdicts.verdicts[0].revoked, null);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: key rotation keeps old verdicts verifiable", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    const oldVerdict = (adj.json() as { verdicts: Array<Record<string, unknown>> }).verdicts[0];
    const keysBefore = (await app.inject({ method: "GET", url: "/v1/keys" })).json() as {
      active: string;
      retired: string[];
    };
    const rotated = await app.inject({ method: "POST", url: "/v1/keys/rotate" });
    assert.equal(rotated.statusCode, 200);
    const keysAfter = rotated.json() as { active: string; retired: string[] };
    assert.notEqual(keysAfter.active, keysBefore.active);
    assert.ok(keysAfter.retired.includes(keysBefore.active));
    // Old verdict verifies against the full trusted set (active + retired).
    const v = verifyVerdict(oldVerdict, {
      trustedArbiters: [keysAfter.active, ...keysAfter.retired],
    });
    assert.equal(v.ok, true, v.errors.join("; "));
    // ...but not against the new key alone.
    const v2 = verifyVerdict(oldVerdict, { trustedArbiters: [keysAfter.active] });
    assert.equal(v2.ok, false);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: mandate-backed hold verifies, replays, and enforces limits", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    onboard("owner");
    const agent = onboard("agent");
    const grant = issueGrant({
      agentDid: agent.did,
      scope: ["agentarb:hold"],
      amountLimit: 100,
    });
    const mint = (amount: number) =>
      mintMandate({
        audience: "agentarb",
        scope: ["agentarb:hold"],
        amount,
        grantJws: grant.grant,
      }).mandate;

    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;

    // Valid mandate hold.
    const mandate = mint(100);
    const hold = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId, claim_index: 0, amount_minor: 5000, currency: "USD", mandate_jws: mandate },
    });
    assert.equal(hold.statusCode, 201, hold.body);
    assert.equal((hold.json() as { mandate_agent: string }).mandate_agent, agent.did);

    // Same mandate again -> replay failure.
    const replay = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId, claim_index: 0, amount_minor: 100, currency: "USD", mandate_jws: mandate },
    });
    assert.equal(replay.statusCode, 400);

    // Fresh mandate, hold above its limit -> rejected.
    const small = mint(10);
    const over = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId, claim_index: 0, amount_minor: 5000, currency: "USD", mandate_jws: small },
    });
    assert.equal(over.statusCode, 400);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: viewer escapes untrusted case data", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const payload = bundlePayload({
      transaction: {
        ref: "<script>alert(1)</script>",
        currency: "USD",
        amount_minor: 10000,
        agreed_delivery_at: "2026-10-01T00:00:00Z",
      },
    });
    const bundle = signedMulti(payload, [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const detail = await app.inject({ method: "GET", url: `/cases/${caseId}` });
    assert.equal(detail.statusCode, 200);
    assert.ok(!detail.body.includes("<script>alert(1)</script>"));
    assert.ok(detail.body.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  } finally {
    await app.close();
    store.close();
  }
});
