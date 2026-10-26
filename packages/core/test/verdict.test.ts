import test from "node:test";
import assert from "node:assert/strict";
import { party } from "./helpers.ts";
import {
  isRevoked,
  signRevocation,
  signVerdict,
  verdictIdFor,
  verdictSignPayload,
  verifyRevocation,
  verifyVerdict,
  type Verdict,
  type VerdictCore,
} from "../dist/index.js";

const arbiter = party(9);
const other = party(10);

function sampleVerdict(): Verdict {
  const core: VerdictCore = {
    format: "agentarb-verdict",
    version: 1,
    case_id: "case-1",
    bundle_id: "bundle-1",
    bundle_hash: "a".repeat(64),
    ruleset_id: "builtin/non-delivery",
    ruleset_version: 1,
    ruleset_hash: "b".repeat(64),
    method: "rules",
    outcome: "refund_full",
    refund_minor: 10000,
    currency: "USD",
    claim_amount_minor: 10000,
    reasoning: [
      { rule: "no-delivery-past-deadline", matched: true, reason: "No proof." },
    ],
    decided_at: "2026-10-10T00:00:00Z",
    arbiter: arbiter.did,
  };
  return { ...core, id: verdictIdFor(verdictSignPayload(core)), signature: null };
}

test("verdict: sign and verify round-trip", () => {
  const signed = signVerdict(sampleVerdict(), arbiter.privateJwk);
  assert.ok(signed.signature);
  const v = verifyVerdict(signed, { trustedArbiters: [arbiter.did] });
  assert.equal(v.ok, true, v.errors.join("; "));
});

test("verdict: untrusted arbiter rejected", () => {
  const signed = signVerdict(sampleVerdict(), arbiter.privateJwk);
  const v = verifyVerdict(signed, { trustedArbiters: [other.did] });
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.includes("not in the trusted set")));
});

test("verdict: tampered verdict fails signature check", () => {
  const signed = signVerdict(sampleVerdict(), arbiter.privateJwk);
  const tampered = { ...signed, refund_minor: 1 };
  assert.equal(verifyVerdict(tampered).ok, false);
});

test("verdict: unsigned verdict rejected unless explicitly allowed", () => {
  assert.equal(verifyVerdict(sampleVerdict()).ok, false);
  assert.equal(
    verifyVerdict(sampleVerdict(), { allowUnsigned: true }).ok,
    true,
  );
});

test("verdict: structural invariants enforced", () => {
  const over = { ...sampleVerdict(), refund_minor: 10001 };
  assert.ok(
    verifyVerdict(over, { allowUnsigned: true }).errors.some((e) =>
      e.includes("must not exceed"),
    ),
  );
  const esc = { ...sampleVerdict(), outcome: "escalate", refund_minor: 500 };
  assert.ok(
    verifyVerdict(esc as Verdict, { allowUnsigned: true }).errors.some((e) =>
      e.includes("escalate verdicts must carry refund_minor 0"),
    ),
  );
  const human = {
    ...sampleVerdict(),
    method: "human",
    ruleset_id: "builtin/non-delivery",
    ruleset_hash: "b".repeat(64),
  };
  assert.ok(
    verifyVerdict(human as Verdict, { allowUnsigned: true }).errors.some((e) =>
      e.includes("must not cite a rule set"),
    ),
  );
});

test("verdict: signing with the wrong key throws", () => {
  assert.throws(
    () => signVerdict(sampleVerdict(), other.privateJwk),
    /does not match verdict.arbiter/,
  );
});

test("revocation: sign, verify, and lookup", () => {
  const entry = signRevocation(
    {
      verdict_id: "v_abc",
      reason: "issued in error",
      revoked_at: "2026-10-11T00:00:00Z",
      arbiter: arbiter.did,
    },
    arbiter.privateJwk,
  );
  const v = verifyRevocation(entry, [arbiter.did]);
  assert.equal(v.ok, true, v.errors.join("; "));
  assert.equal(isRevoked([entry], "v_abc")?.reason, "issued in error");
  assert.equal(isRevoked([entry], "v_other"), null);
  const tampered = { ...entry, reason: "different" };
  assert.equal(verifyRevocation(tampered, [arbiter.did]).ok, false);
});

test("verdict: human verdict citing only ruleset_version is rejected", () => {
  const human = {
    ...sampleVerdict(),
    method: "human",
    ruleset_version: 1,
  };
  delete (human as Record<string, unknown>).ruleset_id;
  delete (human as Record<string, unknown>).ruleset_hash;
  assert.ok(
    verifyVerdict(human as Verdict, { allowUnsigned: true }).errors.some((e) =>
      e.includes("must not cite a rule set"),
    ),
  );
});

test("verdict: id swapped post-signing fails verification (revocation evasion)", () => {
  // M1: the signature covers the payload but not the id, so without a
  // content-address check a revoked verdict could be re-labeled and
  // presented to an offline consumer as live.
  const signed = signVerdict(sampleVerdict(), arbiter.privateJwk);
  assert.equal(verifyVerdict(signed).ok, true);
  const mutated = { ...signed, id: "v_" + "0".repeat(64) };
  const v = verifyVerdict(mutated);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.includes("content address")));
  // And the revocation for the original id does not match the mutant.
  const entry = signRevocation(
    {
      verdict_id: signed.id,
      reason: "fraud",
      revoked_at: "2026-10-11T00:00:00Z",
      arbiter: arbiter.did,
    },
    arbiter.privateJwk,
  );
  assert.equal(isRevoked([entry], signed.id)?.reason, "fraud");
  assert.equal(isRevoked([entry], mutated.id), null);
});

test("verdict: signing a verdict with a non-content id throws", () => {
  assert.throws(
    () => signVerdict({ ...sampleVerdict(), id: "v_not_the_address" }, arbiter.privateJwk),
    /content address/,
  );
});
