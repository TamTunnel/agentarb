import test from "node:test";
import assert from "node:assert/strict";
import {
  basePayload,
  party,
  signedBundle,
  signedEvidence,
} from "./helpers.ts";
import {
  adjudicateClaim,
  adjudicateClaimWithEvidence,
  bundleHash,
  builtinRulesetFor,
  canonicalize,
  signVerdict,
  verifyVerdict,
} from "../dist/index.js";

const claimant = party(1);
const respondent = party(2);
const oracle = party(3);
const arbiter = party(9);

const DEADLINE = "2026-10-01T00:00:00Z";
const NOW_AFTER = new Date("2026-10-10T00:00:00Z");
const NOW_BEFORE = new Date("2026-09-15T00:00:00Z");

function nonDeliveryBundle(evidence: unknown[] = []) {
  const payload = basePayload();
  payload.evidence = evidence as never[];
  return signedBundle(payload, [claimant]);
}

function lateBundle(evidence: unknown[] = []) {
  const payload = basePayload();
  payload.claims = [
    { type: "late-delivery", amount_minor: 10000, details: { penalty_minor: 1500 } },
  ];
  payload.evidence = evidence as never[];
  return signedBundle(payload, [claimant]);
}

function wrongBundle(evidence: unknown[] = [], details: Record<string, unknown> = {}) {
  const payload = basePayload();
  payload.claims = [
    { type: "wrong-partial-delivery", amount_minor: 10000, details },
  ];
  payload.evidence = evidence as never[];
  return signedBundle(payload, [claimant]);
}

test("engine: non-delivery with no proof past deadline refunds in full", () => {
  const bundle = nonDeliveryBundle();
  const { verdict, firedRule } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("non-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "refund_full");
  assert.equal(verdict.refund_minor, 10000);
  assert.equal(firedRule, "no-delivery-past-deadline");
  assert.equal(verdict.method, "rules");
  assert.equal(verdict.ruleset_id, "builtin/non-delivery");
});

test("engine: non-delivery with credible delivery proof is rejected", () => {
  const proof = signedEvidence(
    {
      id: "ev-delivery",
      kind: "delivery-proof",
      content: "carrier scan 2026-09-30",
      delivered_at: "2026-09-30T00:00:00Z",
      submitted_by: claimant.did,
    },
    oracle,
  );
  const bundle = nonDeliveryBundle([proof]);
  const { verdict, firedRule } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("non-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "reject");
  assert.equal(verdict.refund_minor, 0);
  assert.equal(firedRule, "credible-delivery-exists");
});

test("engine: non-delivery with only self-signed delivery proof escalates", () => {
  const proof = signedEvidence(
    {
      id: "ev-delivery",
      kind: "delivery-proof",
      content: "I delivered it, trust me",
      submitted_by: respondent.did,
    },
    respondent,
  );
  const bundle = nonDeliveryBundle([proof]);
  const { verdict, firedRule } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("non-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "escalate");
  assert.equal(verdict.refund_minor, 0);
  assert.equal(firedRule, "weak-delivery-claim");
});

test("engine: non-delivery before the deadline escalates (premature)", () => {
  const bundle = nonDeliveryBundle();
  const { verdict } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("non-delivery"),
    "case-1",
    arbiter.did,
    NOW_BEFORE,
  );
  assert.equal(verdict.outcome, "escalate");
});

test("engine: late delivery after deadline refunds the penalty", () => {
  const proof = signedEvidence(
    {
      id: "ev-delivery",
      kind: "delivery-proof",
      content: "carrier scan",
      delivered_at: "2026-10-03T00:00:00Z",
      submitted_by: claimant.did,
    },
    oracle,
  );
  const bundle = lateBundle([proof]);
  const { verdict, firedRule } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("late-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "refund_partial");
  assert.equal(verdict.refund_minor, 1500);
  assert.equal(firedRule, "delivered-late");
});

test("engine: on-time delivery rejects a late claim", () => {
  const proof = signedEvidence(
    {
      id: "ev-delivery",
      kind: "delivery-proof",
      content: "carrier scan",
      delivered_at: "2026-09-30T00:00:00Z",
      submitted_by: claimant.did,
    },
    oracle,
  );
  const bundle = lateBundle([proof]);
  const { verdict } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("late-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "reject");
});

test("engine: late claim with no credible timestamp escalates", () => {
  const bundle = lateBundle();
  const { verdict } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("late-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "escalate");
});

test("engine: wrong-partial with missing amount refunds it", () => {
  const proof = signedEvidence(
    {
      id: "ev-condition",
      kind: "condition-proof",
      content: "inspection: 2 of 5 crates missing",
      submitted_by: claimant.did,
    },
    oracle,
  );
  const bundle = wrongBundle([proof], { missing_minor: 3000 });
  const { verdict, firedRule } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("wrong-partial-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "refund_partial");
  assert.equal(verdict.refund_minor, 3000);
  assert.equal(firedRule, "missing-amount");
});

test("engine: wrong-partial with delivered fraction refunds the rest", () => {
  const proof = signedEvidence(
    {
      id: "ev-condition",
      kind: "condition-proof",
      content: "inspection: 3/4 delivered",
      submitted_by: claimant.did,
    },
    oracle,
  );
  const bundle = wrongBundle([proof], {
    delivered_fraction: { numerator: 3, denominator: 4 },
  });
  const { verdict, firedRule } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("wrong-partial-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "refund_partial");
  assert.equal(verdict.refund_minor, 2500);
  assert.equal(firedRule, "delivered-fraction");
});

test("engine: wrong-partial with no credible condition evidence escalates", () => {
  const bundle = wrongBundle([], { missing_minor: 3000 });
  const { verdict } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("wrong-partial-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "escalate");
});

test("engine: wrong-partial fully delivered rejects", () => {
  const proof = signedEvidence(
    {
      id: "ev-condition",
      kind: "condition-proof",
      content: "inspection: all present",
      submitted_by: claimant.did,
    },
    oracle,
  );
  const bundle = wrongBundle([proof], {
    delivered_fraction: { numerator: 1, denominator: 1 },
  });
  const { verdict } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("wrong-partial-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "reject");
});

test("engine: determinism — same bundle + rules + time = byte-identical verdict", () => {
  const bundle = nonDeliveryBundle();
  const rs = builtinRulesetFor("non-delivery");
  const a = adjudicateClaim(bundle, 0, rs, "case-1", arbiter.did, NOW_AFTER);
  const b = adjudicateClaim(bundle, 0, rs, "case-1", arbiter.did, NOW_AFTER);
  assert.equal(canonicalize(a.verdict), canonicalize(b.verdict));
  assert.equal(a.verdict.id, b.verdict.id);
  // Ed25519 signatures are deterministic too: signed verdicts match.
  const sa = signVerdict(a.verdict, arbiter.privateJwk);
  const sb = signVerdict(b.verdict, arbiter.privateJwk);
  assert.equal(sa.signature, sb.signature);
  assert.equal(verifyVerdict(sa, { trustedArbiters: [arbiter.did] }).ok, true);
});

test("engine: refund never exceeds the claim", () => {
  // Fraction refund computed on the full tx amount but capped by the claim:
  // tx 10000, fraction 0/4 -> refund 10000, claim 4000 -> must escalate,
  // never silently clamp.
  const proof = signedEvidence(
    {
      id: "ev-condition",
      kind: "condition-proof",
      content: "nothing delivered",
      submitted_by: claimant.did,
    },
    oracle,
  );
  const payload = basePayload();
  payload.claims = [
    {
      type: "wrong-partial-delivery",
      amount_minor: 4000,
      details: { delivered_fraction: { numerator: 0, denominator: 4 } },
    },
  ];
  payload.evidence = [proof];
  const bundle = signedBundle(payload, [claimant]);
  const { verdict } = adjudicateClaim(
    bundle,
    0,
    builtinRulesetFor("wrong-partial-delivery"),
    "case-1",
    arbiter.did,
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "escalate");
  assert.equal(verdict.refund_minor, 0);
});

test("engine: refuses to adjudicate an unverified bundle", () => {
  const bundle = nonDeliveryBundle();
  const tampered = { ...bundle, id: "bundle-2" };
  assert.throws(
    () =>
      adjudicateClaim(
        tampered,
        0,
        builtinRulesetFor("non-delivery"),
        "case-1",
        arbiter.did,
        NOW_AFTER,
      ),
    /unverified bundle/,
  );
});

test("engine: wrong rule set for the claim type throws", () => {
  const bundle = nonDeliveryBundle();
  assert.throws(
    () =>
      adjudicateClaim(
        bundle,
        0,
        builtinRulesetFor("late-delivery"),
        "case-1",
        arbiter.did,
        NOW_AFTER,
      ),
    /covers late-delivery, not non-delivery/,
  );
});

test("engine: adjudication with pre-verified evidence added after signing", () => {
  // The claimant signed a bundle with no evidence. Later, an oracle
  // delivery proof is added — the envelope no longer covers the rebuilt
  // payload, so plain adjudicateClaim must refuse it, but
  // adjudicateClaimWithEvidence (given the individually verified item)
  // decides on the full evidence set.
  const bundle = nonDeliveryBundle();
  const proof = signedEvidence(
    {
      id: "ev-delivery",
      kind: "delivery-proof",
      content: "carrier scan",
      delivered_at: "2026-09-30T00:00:00Z",
      submitted_by: claimant.did,
    },
    oracle,
  );
  const rebuilt = { ...bundle, evidence: [proof] };
  assert.throws(
    () =>
      adjudicateClaim(
        rebuilt,
        0,
        builtinRulesetFor("non-delivery"),
        "case-1",
        arbiter.did,
        NOW_AFTER,
      ),
    /unverified bundle/,
  );
  const { verdict } = adjudicateClaimWithEvidence(
    rebuilt,
    0,
    builtinRulesetFor("non-delivery"),
    "case-1",
    arbiter.did,
    [{ item: proof, tier: 2, tierName: "third-party-oracle-signed" }],
    bundleHash(bundle),
    NOW_AFTER,
  );
  assert.equal(verdict.outcome, "reject");
});
