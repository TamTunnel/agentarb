import test from "node:test";
import assert from "node:assert/strict";
import { party } from "./helpers.ts";
import {
  isRevoked,
  signRevocation,
  signVerdict,
  verifyRevocation,
  verifyVerdict,
  type Verdict,
} from "../dist/index.js";

const arbiter = party(9);
const other = party(10);

function sampleVerdict(): Verdict {
  return {
    format: "agentarb-verdict",
    version: 1,
    id: "v_abc",
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
    signature: null,
  };
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
