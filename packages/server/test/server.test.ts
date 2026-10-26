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
  bundleHash,
  evidenceSignPayload,
  signVerdict,
  verifyVerdict,
  verdictIdFor,
  verdictSignPayload,
  type Bundle,
  type Keypair,
  type Verdict,
} from "@tamtunnel/agentarb-core";
import { createApp } from "../dist/app.js";
import { Store } from "../dist/store.js";
import { applyVerdictToEscrow } from "../dist/escrow.js";

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

/** Build a human verdict with a real bundle hash and content-addressed id. */
function humanVerdict(
  caseId: string,
  bundleHashValue: string,
  signer: Keypair,
  overrides: Record<string, unknown> = {},
): Verdict {
  const core = {
    format: "agentarb-verdict",
    version: 1,
    case_id: caseId,
    bundle_id: "bundle-1",
    bundle_hash: bundleHashValue,
    method: "human",
    outcome: "refund_partial",
    refund_minor: 5000,
    currency: "USD",
    claim_amount_minor: 10000,
    reasoning: [{ rule: "human-review", matched: true, reason: "Split the difference." }],
    decided_at: "2026-10-11T00:00:00Z",
    arbiter: signer.did,
    ...overrides,
  };
  const id = verdictIdFor(verdictSignPayload(core));
  return signVerdict(
    { ...core, id, signature: null } as Verdict,
    signer.privateJwk,
  );
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
    const hvVerdict = humanVerdict(caseId, body.bundle_hash as string, human);
    const hv = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/human-verdict`,
      payload: { verdict: hvVerdict, claim_index: 0 },
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
    const hvVerdict = humanVerdict(caseId, body.bundle_hash as string, human, {
      outcome: "reject",
      refund_minor: 0,
      reasoning: [{ rule: "human-review", matched: true, reason: "No." }],
    });
    const hv = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/human-verdict`,
      payload: { verdict: hvVerdict, claim_index: 0 },
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

test("server: claims summing over the transaction are rejected (M1)", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    // The gate's exact probe: 10000 tx, deadline passed, no delivery
    // proof — non-delivery refund_full 10000 AND wrong-partial 3000
    // would pay 13000 on contradictory theories of the same loss.
    const payload = bundlePayload({
      claims: [
        { type: "non-delivery", amount_minor: 10000, details: {} },
        {
          type: "wrong-partial-delivery",
          amount_minor: 3000,
          details: { missing_minor: 3000 },
        },
      ],
    });
    const bundle = signedMulti(payload, [claimant]);
    const res = await submitCase(app, bundle);
    assert.equal(res.status, 400, JSON.stringify(res.body));
    assert.match(JSON.stringify(res.body), /sum of claim amounts/);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: pre-fix over-claim bundle fails closed at adjudication (M1)", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    // A bundle stored before the sum cap existed must still never pay
    // out: the engine re-verifies per claim, so adjudication fails
    // before any verdict is saved.
    const payload = bundlePayload({
      claims: [
        { type: "non-delivery", amount_minor: 10000, details: {} },
        {
          type: "wrong-partial-delivery",
          amount_minor: 3000,
          details: { missing_minor: 3000 },
        },
      ],
    });
    const bundle = signedMulti(payload, [claimant]);
    const caseId = "case_prefix";
    store.createCase(caseId, bundle, bundleHash(bundle), "2026-10-25T00:00:00Z");
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal(adj.statusCode, 400, adj.body);
    const verdicts = (await app.inject({
      method: "GET",
      url: `/v1/cases/${caseId}/verdicts`,
    })).json() as { verdicts: unknown[] };
    assert.deepEqual(verdicts.verdicts, []);
    const detail = (await app.inject({
      method: "GET",
      url: `/v1/cases/${caseId}`,
    })).json() as { status: string };
    assert.equal(detail.status, "open");
  } finally {
    await app.close();
    store.close();
  }
});

test("server: mid-loop adjudication failure rolls everything back (M2)", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    // Two byte-identical claims produce the same content-addressed
    // verdict id, so claim 1's save throws mid-loop. The transaction
    // must roll claim 0's verdict and escrow movement back.
    const payload = bundlePayload({
      claims: [
        { type: "non-delivery", amount_minor: 5000, details: {} },
        { type: "non-delivery", amount_minor: 5000, details: {} },
      ],
    });
    const bundle = signedMulti(payload, [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const hold = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId, claim_index: 0, amount_minor: 5000, currency: "USD" },
    });
    assert.equal(hold.statusCode, 201, hold.body);
    const holdId = (hold.json() as { hold_id: string }).hold_id;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal(adj.statusCode, 400, adj.body);
    const verdicts = (await app.inject({
      method: "GET",
      url: `/v1/cases/${caseId}/verdicts`,
    })).json() as { verdicts: unknown[] };
    assert.deepEqual(verdicts.verdicts, []);
    const holdAfter = (await app.inject({
      method: "GET",
      url: `/v1/holds/${holdId}`,
    })).json() as { status: string; remaining_minor: number };
    assert.equal(holdAfter.status, "held");
    assert.equal(holdAfter.remaining_minor, 5000);
    const detail = (await app.inject({
      method: "GET",
      url: `/v1/cases/${caseId}`,
    })).json() as { status: string };
    assert.equal(detail.status, "open");
  } finally {
    await app.close();
    store.close();
  }
});

test("server: multi-claim adjudication commits all verdicts (M2 happy path)", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bare = {
      id: "ev-condition",
      kind: "condition-proof",
      content: "inspection: 4000 worth missing",
      submitted_by: claimant.did,
    };
    const proof = {
      ...bare,
      signer: oracle.did,
      jws: signJws(evidenceSignPayload({ ...bare, signer: null, jws: null } as never), oracle.privateJwk),
    };
    const payload = bundlePayload({
      claims: [
        { type: "non-delivery", amount_minor: 6000, details: {} },
        {
          type: "wrong-partial-delivery",
          amount_minor: 4000,
          details: { missing_minor: 4000 },
        },
      ],
      evidence: [proof],
    });
    const bundle = signedMulti(payload, [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal(adj.statusCode, 200, adj.body);
    const adjBody = adj.json() as {
      status: string;
      verdicts: Array<Record<string, unknown>>;
    };
    assert.equal(adjBody.status, "adjudicated");
    assert.equal(adjBody.verdicts.length, 2);
    assert.equal(adjBody.verdicts[0].outcome, "refund_full");
    assert.equal(adjBody.verdicts[0].refund_minor, 6000);
    assert.equal(adjBody.verdicts[1].outcome, "refund_partial");
    assert.equal(adjBody.verdicts[1].refund_minor, 4000);
    assert.notEqual(adjBody.verdicts[0].id, adjBody.verdicts[1].id);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: human verdict checks — hash, content id, self-dealing (M3)", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
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
    const realHash = body.bundle_hash as string;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal((adj.json() as { status: string }).status, "escalated");

    const post = (verdict: unknown) =>
      app.inject({
        method: "POST",
        url: `/v1/cases/${caseId}/human-verdict`,
        payload: { verdict, claim_index: 0 },
      });

    // Wrong bundle hash (with a matching content id for that payload).
    const wrongHash = humanVerdict(caseId, "0".repeat(64), human);
    assert.equal((await post(wrongHash)).statusCode, 400);

    // Non-content-addressed id, correct hash.
    const core = {
      format: "agentarb-verdict",
      version: 1,
      case_id: caseId,
      bundle_id: "bundle-1",
      bundle_hash: realHash,
      method: "human",
      outcome: "refund_partial",
      refund_minor: 5000,
      currency: "USD",
      claim_amount_minor: 10000,
      reasoning: [{ rule: "human-review", matched: true, reason: "Split." }],
      decided_at: "2026-10-11T00:00:00Z",
      arbiter: human.did,
    };
    // Non-content-addressed id, correct hash. signVerdict now refuses
    // to mint such a verdict, so sign the payload directly: the server
    // must still reject the signature-valid, wrong-id verdict.
    const nonContent = {
      ...core,
      id: "v_not_content",
      signature: signJws(verdictSignPayload(core as never), human.privateJwk),
    };
    assert.equal((await post(nonContent)).statusCode, 400);

    // Self-dealing: the claimant signing their own "human verdict".
    const selfDealing = humanVerdict(caseId, realHash, claimant);
    assert.equal((await post(selfDealing)).statusCode, 400);

    // Escalate is not a human outcome — the human IS the escalation.
    const escalate = humanVerdict(caseId, realHash, human, {
      outcome: "escalate",
      refund_minor: 0,
    });
    assert.equal((await post(escalate)).statusCode, 400);

    // The case is untouched by all four rejections and still resolves.
    const good = humanVerdict(caseId, realHash, human);
    const ok = await post(good);
    assert.equal(ok.statusCode, 200, ok.body);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: escrow refund-reject-refund cannot double-pay (M4)", async () => {
  const store = new Store(":memory:");
  try {
    const now = "2026-10-25T00:00:00Z";
    store.createCase("case_m4", { id: "b1" }, "a".repeat(64), now);
    // Full trace: refund 10000 (hold A drained), reject (applied reset),
    // new hold B 10000, refund 10000 again — second refund must move 0.
    store.createHold("hold_a", "case_m4", 0, 10000, "USD", null, null, now);
    store.addHoldEvent("hold_a", "hold", 10000, null, now);
    const fx1 = applyVerdictToEscrow(store, "case_m4", 0, "v1", "refund_full", 10000, now, 10000);
    assert.equal(fx1.length, 1);
    assert.equal(fx1[0].kind, "refund");
    assert.equal(fx1[0].amount_minor, 10000);
    const fx2 = applyVerdictToEscrow(store, "case_m4", 0, "v2", "reject", 0, now, 10000);
    assert.deepEqual(fx2, []);
    assert.equal(store.getAppliedRefund("case_m4", 0), 0);
    assert.equal(store.getCumulativeRefund("case_m4", 0), 10000);
    store.createHold("hold_b", "case_m4", 0, 10000, "USD", null, null, now);
    store.addHoldEvent("hold_b", "hold", 10000, null, now);
    const fx3 = applyVerdictToEscrow(store, "case_m4", 0, "v3", "refund_full", 10000, now, 10000);
    assert.deepEqual(fx3, []);
    const holdB = store.getHold("hold_b");
    assert.equal(holdB?.remaining_minor, 10000);

    // Partial variant: refund 6000, reject, new hold, refund 10000 — only
    // the 4000 headroom may move.
    store.createCase("case_m4b", { id: "b2" }, "a".repeat(64), now);
    store.createHold("hold_c", "case_m4b", 0, 10000, "USD", null, null, now);
    store.addHoldEvent("hold_c", "hold", 10000, null, now);
    const g1 = applyVerdictToEscrow(store, "case_m4b", 0, "v1", "refund_partial", 6000, now, 10000);
    assert.equal(g1[0].amount_minor, 6000);
    const g2 = applyVerdictToEscrow(store, "case_m4b", 0, "v2", "reject", 0, now, 10000);
    assert.equal(g2.length, 1);
    assert.equal(g2[0].kind, "release");
    assert.equal(g2[0].amount_minor, 4000);
    store.createHold("hold_d", "case_m4b", 0, 10000, "USD", null, null, now);
    store.addHoldEvent("hold_d", "hold", 10000, null, now);
    const g3 = applyVerdictToEscrow(store, "case_m4b", 0, "v3", "refund_full", 10000, now, 10000);
    assert.equal(g3.length, 1);
    assert.equal(g3[0].amount_minor, 4000);
    assert.equal(store.getHold("hold_d")?.remaining_minor, 6000);
    assert.equal(store.getCumulativeRefund("case_m4b", 0), 10000);
  } finally {
    store.close();
  }
});

test("server: re-adjudication deltas — escalate then refund, refund then reject", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    // Escalate (window still open) then refund (deadline passed).
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const early = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-09-15T00:00:00Z" },
    });
    assert.equal((early.json() as { status: string }).status, "escalated");
    const late = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal(late.statusCode, 200, late.body);
    const lateBody = late.json() as { verdicts: Array<Record<string, unknown>> };
    assert.equal(lateBody.verdicts.length, 1);
    assert.equal(lateBody.verdicts[0].outcome, "refund_full");
    const allVerdicts = (await app.inject({
      method: "GET",
      url: `/v1/cases/${caseId}/verdicts`,
    })).json() as { verdicts: Array<Record<string, unknown>> };
    assert.equal(allVerdicts.verdicts.length, 2);
    assert.deepEqual(
      allVerdicts.verdicts.map((v) => v.outcome).sort(),
      ["escalate", "refund_full"],
    );

    // Refund then reject: credible delivery proof added after the refund.
    const bundle2 = signedMulti(bundlePayload({ id: "bundle-2" }), [claimant]);
    const body2 = (await submitCase(app, bundle2)).body;
    const caseId2 = body2.case_id as string;
    const hold = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId2, claim_index: 0, amount_minor: 10000, currency: "USD" },
    });
    const holdId = (hold.json() as { hold_id: string }).hold_id;
    const adj1 = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId2}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal((adj1.json() as { verdicts: Array<Record<string, unknown>> }).verdicts[0].outcome, "refund_full");
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
    const added = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId2}/evidence`,
      payload: { evidence: proof },
    });
    assert.equal(added.statusCode, 201, added.body);
    const adj2 = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId2}/adjudicate`,
      payload: { now: "2026-10-10T00:00:00Z" },
    });
    assert.equal(adj2.statusCode, 200, adj2.body);
    const adj2Body = adj2.json() as {
      verdicts: Array<Record<string, unknown>>;
      escrow: Array<Record<string, unknown>>;
    };
    assert.equal(adj2Body.verdicts[0].outcome, "reject");
    assert.deepEqual(adj2Body.escrow, []);
    const holdAfter = (await app.inject({
      method: "GET",
      url: `/v1/holds/${holdId}`,
    })).json() as {
      status: string;
      events: Array<{ kind: string; amount_minor: number }>;
    };
    assert.equal(holdAfter.status, "refunded");
    const refunded = holdAfter.events
      .filter((e) => e.kind === "refund")
      .reduce((s, e) => s + e.amount_minor, 0);
    assert.equal(refunded, 10000);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: database files are mode 0600 (M5)", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentarb-perms-"));
  const dbPath = path.join(dir, "agentarb.db");
  const fileStore = new Store(dbPath);
  try {
    fileStore.createCase("c1", { id: "b1" }, "a".repeat(64), "2026-10-25T00:00:00Z");
    assert.equal(fs.statSync(dbPath).mode & 0o777, 0o600);
    for (const side of ["-wal", "-shm"]) {
      const p = dbPath + side;
      if (fs.existsSync(p)) {
        assert.equal(fs.statSync(p).mode & 0o777, 0o600);
      }
    }
  } finally {
    fileStore.close();
  }
});

test("server: holds capped at claim amount and rejected on resolved cases", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const over = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId, claim_index: 0, amount_minor: 10001, currency: "USD" },
    });
    assert.equal(over.statusCode, 400, over.body);
    // Resolve the case, then holds must stop.
    await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/escalate`,
      payload: {},
    });
    const hvVerdict = humanVerdict(caseId, body.bundle_hash as string, human);
    const hv = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/human-verdict`,
      payload: { verdict: hvVerdict, claim_index: 0 },
    });
    assert.equal(hv.statusCode, 200, hv.body);
    const late = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId, claim_index: 0, amount_minor: 100, currency: "USD" },
    });
    assert.equal(late.statusCode, 409, late.body);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: add-evidence enforces the http(s) URI scheme", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const ftp = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/evidence`,
      payload: {
        evidence: {
          id: "ev-ftp",
          kind: "other",
          content: "x",
          uri: "ftp://example.com/x",
          submitted_by: claimant.did,
        },
      },
    });
    assert.equal(ftp.statusCode, 400, ftp.body);
    const https = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/evidence`,
      payload: {
        evidence: {
          id: "ev-https",
          kind: "other",
          content: "x",
          uri: "https://example.com/x",
          submitted_by: claimant.did,
        },
      },
    });
    assert.equal(https.statusCode, 201, https.body);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: deeply nested bundle returns 400, not 500", async () => {
  const { app, store } = makeApp();
  await ready(app);
  try {
    const payload = bundlePayload();
    let deep: Record<string, unknown> = {};
    let cursor = deep;
    for (let i = 0; i < 2000; i++) {
      const next: Record<string, unknown> = {};
      cursor.nested = next;
      cursor = next;
    }
    (payload.claims as Array<Record<string, unknown>>)[0].details = deep;
    (payload as Record<string, unknown>).signatures = [
      { signer: claimant.did, jws: "junk.junk.junk" },
    ];
    const res = await app.inject({
      method: "POST",
      url: "/v1/cases",
      payload: { bundle: payload },
    });
    assert.equal(res.statusCode, 400, res.body);
    assert.match(res.body, /bundle verification failed/);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: add-evidence rejects unsigned extra fields (shallow and deep)", async () => {
  // m2: the evidence schema must not accept — let alone persist —
  // fields outside the evidence shape, however deeply nested.
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const base = {
      id: "ev-extra",
      kind: "other",
      content: "x",
      submitted_by: claimant.did,
    };
    const shallow = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/evidence`,
      payload: { evidence: { ...base, unsigned_note: "looks official", admin: true } },
    });
    assert.equal(shallow.statusCode, 400, shallow.body);
    let deepExtra: Record<string, unknown> = { leaf: 1 };
    for (let i = 0; i < 200; i++) deepExtra = { nest: deepExtra };
    const deep = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/evidence`,
      payload: { evidence: { ...base, extra: deepExtra } },
    });
    assert.equal(deep.statusCode, 400, deep.body.slice(0, 200));
    // And the server is still alive after the deep body.
    const health = await app.inject({ method: "GET", url: "/health" });
    assert.equal(health.statusCode, 200);
    // Nothing persisted: case detail shows no extra-field evidence.
    const detail = await app.inject({ method: "GET", url: `/v1/cases/${caseId}` });
    assert.deepEqual((detail.json() as { evidence: unknown[] }).evidence, []);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: add-evidence rejects garbage delivered_at like the bundle path", async () => {
  // m3
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const res = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/evidence`,
      payload: {
        evidence: {
          id: "ev-garbage",
          kind: "delivery-proof",
          content: "x",
          delivered_at: "not-a-date",
          submitted_by: claimant.did,
        },
      },
    });
    assert.equal(res.statusCode, 400, res.body);
    assert.match(res.body, /delivered_at/);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: identical-claims adjudication fails cleanly, no SQLite leak", async () => {
  // m8: two identical claims produce identical verdict ids; the UNIQUE
  // failure must surface as a clean 400 with a full rollback.
  const { app, store } = makeApp();
  await ready(app);
  try {
    const payload = bundlePayload({
      claims: [
        { type: "non-delivery", amount_minor: 5000, details: {} },
        { type: "non-delivery", amount_minor: 5000, details: {} },
      ],
    });
    const bundle = signedMulti(payload, [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const res = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: {},
    });
    assert.equal(res.statusCode, 400, res.body);
    assert.doesNotMatch(res.body, /UNIQUE constraint/);
    assert.match(res.body, /identical claims/);
    const detail = await app.inject({ method: "GET", url: `/v1/cases/${caseId}` });
    assert.equal((detail.json() as { status: string }).status, "open");
    assert.deepEqual((detail.json() as { verdicts: unknown[] }).verdicts, []);
  } finally {
    await app.close();
    store.close();
  }
});

test("server: hold created after a refund verdict funds it via the endpoint", async () => {
  // m11 (endpoint wiring): adjudicate with no hold, then add one — the
  // hold must immediately refund the outstanding verdict amount.
  const { app, store } = makeApp();
  await ready(app);
  try {
    const bundle = signedMulti(bundlePayload(), [claimant]);
    const { body } = await submitCase(app, bundle);
    const caseId = body.case_id as string;
    const adj = await app.inject({
      method: "POST",
      url: `/v1/cases/${caseId}/adjudicate`,
      payload: {},
    });
    assert.equal(adj.statusCode, 200, adj.body);
    const verdicts = (adj.json() as { verdicts: Array<{ outcome: string }> }).verdicts;
    assert.equal(verdicts[0].outcome, "refund_full");
    const hold = await app.inject({
      method: "POST",
      url: "/v1/holds",
      payload: { case_id: caseId, claim_index: 0, amount_minor: 10000, currency: "USD" },
    });
    assert.equal(hold.statusCode, 201, hold.body);
    const holdJson = hold.json() as {
      status: string;
      remaining_minor: number;
      escrow: Array<{ kind: string; amount_minor: number }>;
    };
    assert.equal(holdJson.status, "refunded");
    assert.equal(holdJson.remaining_minor, 0);
    assert.equal(holdJson.escrow.length, 1);
    assert.equal(holdJson.escrow[0].kind, "refund");
    assert.equal(holdJson.escrow[0].amount_minor, 10000);
  } finally {
    await app.close();
    store.close();
  }
});
