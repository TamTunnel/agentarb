import test from "node:test";
import assert from "node:assert/strict";
import {
  builtinRulesetFor,
  builtinSignerDid,
  loadBuiltinRulesets,
  verifyRuleset,
} from "../dist/index.js";

test("rulesets: all three built-ins load and verify", () => {
  const sets = loadBuiltinRulesets();
  assert.equal(sets.length, 3);
  const ids = sets.map((s) => s.id).sort();
  assert.deepEqual(ids, [
    "builtin/late-delivery",
    "builtin/non-delivery",
    "builtin/wrong-partial-delivery",
  ]);
  for (const s of sets) {
    assert.equal(s.signer, builtinSignerDid());
    assert.equal(s.version, 1);
  }
});

test("rulesets: tampered rule content fails hash and signature", () => {
  const rs = builtinRulesetFor("non-delivery");
  const tampered = JSON.parse(JSON.stringify(rs));
  tampered.rules[0].outcome = "refund_full";
  const v = verifyRuleset(tampered, { trustedSigners: [builtinSignerDid()] });
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.includes("hash does not match")));
});

test("rulesets: untrusted signer rejected", () => {
  const rs = builtinRulesetFor("non-delivery");
  const v = verifyRuleset(rs, { trustedSigners: ["did:key:z111111111111111111111111111111111111111111111111111111111111111"] });
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.includes("not in the trusted set")));
});

test("rulesets: min tier below the claim-type floor is invalid", () => {
  const rs = builtinRulesetFor("late-delivery");
  const lowered = JSON.parse(JSON.stringify(rs));
  lowered.min_evidence_tier = 1; // late-delivery floor is 2
  const v = verifyRuleset(lowered);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.includes("claim type floor")));
});

test("rulesets: duplicate rule names rejected", () => {
  const rs = builtinRulesetFor("non-delivery");
  const duped = JSON.parse(JSON.stringify(rs));
  duped.rules[1].name = duped.rules[0].name;
  const v = verifyRuleset(duped);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.includes("duplicates")));
});
