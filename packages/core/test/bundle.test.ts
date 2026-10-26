import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  basePayload,
  party,
  signedBundle,
  signedEvidence,
} from "./helpers.ts";
import {
  filterEvidenceForClaim,
  validateBundlePayload,
  verifyBundle,
  verifyEvidenceItem,
} from "../dist/index.js";

const claimant = party(1);
const respondent = party(2);
const oracle = party(3);

test("bundle: valid bundle verifies with claimant signature", () => {
  const bundle = signedBundle(basePayload(), [claimant]);
  const v = verifyBundle(bundle);
  assert.equal(v.ok, true, v.errors.join("; "));
  assert.deepEqual(v.signers, [claimant.did]);
  assert.match(v.hash || "", /^[0-9a-f]{64}$/);
});

test("bundle: multi-party signing works", () => {
  const bundle = signedBundle(basePayload(), [claimant, respondent]);
  const v = verifyBundle(bundle);
  assert.equal(v.ok, true, v.errors.join("; "));
  assert.deepEqual(v.signers.sort(), [claimant.did, respondent.did].sort());
});

test("bundle: missing claimant signature fails", () => {
  const bundle = signedBundle(basePayload(), [respondent]);
  const v = verifyBundle(bundle);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.includes("claimant has not signed")));
});

test("bundle: tampered payload fails signature check", () => {
  const bundle = signedBundle(basePayload(), [claimant]);
  const tampered = {
    ...bundle,
    transaction: { ...bundle.transaction, amount_minor: 99999 },
  };
  const v = verifyBundle(tampered);
  assert.equal(v.ok, false);
});

test("bundle: validation catches float money and over-claims", () => {
  const floatAmount = basePayload();
  (floatAmount.transaction as { amount_minor: unknown }).amount_minor = 10.5;
  assert.ok(
    validateBundlePayload(floatAmount).some((e) => e.includes("amount_minor")),
  );
  const overClaim = basePayload();
  overClaim.claims[0].amount_minor = 20000;
  assert.ok(
    validateBundlePayload(overClaim).some((e) => e.includes("must not exceed")),
  );
});

test("bundle: late-delivery requires penalty_minor", () => {
  const payload = basePayload();
  payload.claims = [
    { type: "late-delivery", amount_minor: 10000, details: {} },
  ];
  assert.ok(
    validateBundlePayload(payload).some((e) => e.includes("penalty_minor")),
  );
  payload.claims = [
    { type: "late-delivery", amount_minor: 10000, details: { penalty_minor: 1500 } },
  ];
  assert.deepEqual(validateBundlePayload(payload), []);
});

test("bundle: wrong-partial requires missing_minor or delivered_fraction", () => {
  const payload = basePayload();
  payload.claims = [
    { type: "wrong-partial-delivery", amount_minor: 10000, details: {} },
  ];
  assert.ok(
    validateBundlePayload(payload).some((e) => e.includes("missing_minor")),
  );
  payload.claims = [
    {
      type: "wrong-partial-delivery",
      amount_minor: 10000,
      details: { delivered_fraction: { numerator: 3, denominator: 4 } },
    },
  ];
  assert.deepEqual(validateBundlePayload(payload), []);
});

test("bundle: evidence tiers — unsigned, self, oracle, counterparty", () => {
  const payload = basePayload();
  payload.evidence = [
    {
      id: "ev-unsigned",
      kind: "communication",
      content: "hello",
      submitted_by: claimant.did,
    },
    signedEvidence(
      {
        id: "ev-self",
        kind: "communication",
        content: "I never got it",
        submitted_by: claimant.did,
      },
      claimant,
    ),
    signedEvidence(
      {
        id: "ev-oracle",
        kind: "delivery-proof",
        content: "carrier scan",
        submitted_by: claimant.did,
      },
      oracle,
    ),
    signedEvidence(
      {
        id: "ev-counterparty",
        kind: "delivery-proof",
        content: "admission",
        submitted_by: claimant.did,
      },
      respondent,
    ),
  ];
  const bundle = signedBundle(payload, [claimant]);
  const v = verifyBundle(bundle);
  assert.equal(v.ok, true, v.errors.join("; "));
  const tiers = Object.fromEntries(v.evidence.map((e) => [e.item.id, e.tier]));
  assert.deepEqual(tiers, {
    "ev-unsigned": 0,
    "ev-self": 1,
    "ev-oracle": 2,
    "ev-counterparty": 3,
  });
});

test("bundle: bad evidence signature fails the whole bundle, never downgrades", () => {
  const good = signedEvidence(
    {
      id: "ev-1",
      kind: "delivery-proof",
      content: "proof",
      submitted_by: claimant.did,
    },
    oracle,
  );
  const tampered = { ...good, content: "forged" };
  const payload = basePayload();
  payload.evidence = [tampered];
  const bundle = signedBundle(payload, [claimant]);
  const v = verifyBundle(bundle);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.includes("ev-1")));
});

test("bundle: signer field disagreeing with the JWS kid fails", () => {
  const item = signedEvidence(
    {
      id: "ev-1",
      kind: "delivery-proof",
      content: "proof",
      submitted_by: claimant.did,
    },
    oracle,
  );
  // Claim a different signer than the JWS kid.
  const lying = { ...item, signer: respondent.did };
  const payload = basePayload();
  payload.evidence = [lying];
  const bundle = signedBundle(payload, [claimant]);
  const v = verifyBundle(bundle);
  assert.equal(v.ok, false);
});

test("bundle: min-tier filtering per claim type", () => {
  const payload = basePayload();
  payload.evidence = [
    { id: "u", kind: "communication", content: "x", submitted_by: claimant.did },
    signedEvidence(
      { id: "s", kind: "communication", content: "x", submitted_by: claimant.did },
      claimant,
    ),
    signedEvidence(
      { id: "o", kind: "delivery-proof", content: "x", submitted_by: claimant.did },
      oracle,
    ),
  ];
  const bundle = signedBundle(payload, [claimant]);
  const v = verifyBundle(bundle);
  assert.equal(v.ok, true, v.errors.join("; "));
  // non-delivery min tier 1: unsigned excluded, self+oracle admitted.
  const nd = filterEvidenceForClaim(v.evidence, "non-delivery");
  assert.deepEqual(nd.admitted.map((e) => e.item.id).sort(), ["o", "s"]);
  assert.deepEqual(nd.excluded.map((e) => e.id), ["u"]);
  // late-delivery min tier 2: only oracle admitted.
  const ld = filterEvidenceForClaim(v.evidence, "late-delivery");
  assert.deepEqual(ld.admitted.map((e) => e.item.id), ["o"]);
  assert.deepEqual(ld.excluded.map((e) => e.id).sort(), ["s", "u"]);
});

test("bundle: sum of claims capped at transaction amount (double recovery)", () => {
  const payload = basePayload();
  payload.claims = [
    { type: "non-delivery", amount_minor: 10000, details: {} },
    {
      type: "wrong-partial-delivery",
      amount_minor: 3000,
      details: { missing_minor: 3000 },
    },
  ];
  // Each claim alone is within the 10000 transaction, but together they
  // claim 13000 on contradictory theories of the same loss.
  const errors = validateBundlePayload(payload);
  assert.ok(
    errors.some((e) => e.includes("sum of claim amounts")),
    errors.join("; "),
  );
  // Exactly at the transaction amount is fine.
  payload.claims = [
    { type: "non-delivery", amount_minor: 6000, details: {} },
    {
      type: "wrong-partial-delivery",
      amount_minor: 4000,
      details: { missing_minor: 4000 },
    },
  ];
  assert.deepEqual(validateBundlePayload(payload), []);
});

test("bundle: party-signed item from a third-party submitter is tier 2, not 3", () => {
  const payload = basePayload();
  payload.evidence = [
    signedEvidence(
      {
        id: "ev-third-party-submission",
        kind: "delivery-proof",
        content: "admission",
        submitted_by: oracle.did,
      },
      respondent,
    ),
  ];
  const bundle = signedBundle(payload, [claimant]);
  const v = verifyBundle(bundle);
  assert.equal(v.ok, true, v.errors.join("; "));
  // Tier 3 requires the admission structure (one party submits, the other
  // signed). A third-party submitter breaks it, so this is tier 2.
  assert.equal(v.evidence[0].tier, 2);
});

test("bundle: deeply nested payload fails verification, never throws", () => {
  const payload = basePayload();
  let deep: Record<string, unknown> = {};
  let cursor = deep;
  for (let i = 0; i < 2000; i++) {
    const next: Record<string, unknown> = {};
    cursor.nested = next;
    cursor = next;
  }
  payload.claims = [
    { type: "non-delivery", amount_minor: 10000, details: deep },
  ];
  const bundle = {
    ...payload,
    signatures: [{ signer: claimant.did, jws: "junk.junk.junk" }],
  };
  const v = verifyBundle(bundle);
  assert.equal(v.ok, false);
  assert.ok(
    v.errors.some((e) => e.includes("depth")),
    v.errors.join("; "),
  );
});

test("bundle: content/sha256 mismatch is rejected; match is accepted", () => {
  // m12: when an item carries both content and sha256, the digest must
  // be the SHA-256 of the content bytes — signed or not.
  const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
  const bad = {
    id: "e-mismatch",
    kind: "other" as const,
    content: "REAL CONTENT",
    sha256: "0".repeat(64),
    submitted_by: claimant.did,
  };
  const vBad = verifyEvidenceItem(bad, claimant.did, respondent.did);
  assert.equal(vBad.ok, false);
  assert.ok(vBad.errors.some((e) => e.includes("sha256 does not match content")));
  const signedBad = signedEvidence(bad, claimant);
  assert.equal(verifyEvidenceItem(signedBad, claimant.did, respondent.did).ok, false);
  const good = {
    id: "e-match",
    kind: "other" as const,
    content: "REAL CONTENT",
    sha256: sha("REAL CONTENT"),
    submitted_by: claimant.did,
  };
  assert.equal(verifyEvidenceItem(good, claimant.did, respondent.did).ok, true);
  assert.equal(verifyEvidenceItem(signedEvidence(good, claimant), claimant.did, respondent.did).ok, true);
  // A sha256 alongside a uri (no inline content) stays an unverified
  // claim about remote bytes — no fetcher in v1 — so it still verifies.
  const remote = {
    id: "e-remote",
    kind: "other" as const,
    uri: "https://example.invalid/file.bin",
    sha256: "0".repeat(64),
    submitted_by: claimant.did,
  };
  assert.equal(verifyEvidenceItem(remote, claimant.did, respondent.did).ok, true);
});
