// packages/server/test/escrow.test.ts
//
// Regression tests for the adversarial-judge mandate + escrow findings:
// kid/issuer binding (C1), rounding (m4), audience (m5), currency (m6),
// scope (m7), downward-revision release status (m10), and the
// post-verdict-hold re-apply path (m11). Direct adapter/store tests with
// fresh mandate jtis per attempt (verifyMandate burns a jti on success,
// so a reused mandate would fail as a replay, not on the policy under
// test).

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  generateKeypair,
  signJws,
  type Keypair,
} from "@tamtunnel/agentarb-core";
import { Store } from "../dist/store.js";
import {
  applyUnfundedRefund,
  applyVerdictToEscrow,
  checkMandateForHold,
} from "../dist/escrow.js";

// Same throwaway-ledger setup as the server tests: the si-wallet-core
// keystore is encrypted and the replay ledger is test-only scratch.
process.env.SI_WALLET_DIR = fs.mkdtempSync(
  path.join(os.tmpdir(), "agentarb-escrow-test-"),
);
process.env.SI_WALLET_PASSPHRASE = "agentarb-test-passphrase-only";

const now = Math.floor(Date.now() / 1000);
let seq = 0;
const freshJti = () => `test-${++seq}-${Math.random().toString(36).slice(2)}`;

function grantJws(
  signerKp: Keypair,
  opts: { iss: string; sub: string; amount: number; scope?: string[]; currency?: string },
) {
  return signJws(
    {
      iss: opts.iss,
      sub: opts.sub,
      aud: "sovereign-identity/agency",
      iat: now - 10,
      exp: now + 86400,
      jti: "grant-" + freshJti(),
      claims: {
        scope: opts.scope ?? ["agentarb:hold"],
        amount_limit: opts.amount,
        currency: opts.currency ?? "USD",
        note: "",
      },
    },
    signerKp.privateJwk,
  );
}

function mandateJws(
  signerKp: Keypair,
  opts: {
    iss: string;
    aud?: string;
    amount: number;
    scope?: string[];
    currency?: string;
    grant: string;
  },
) {
  return signJws(
    {
      iss: opts.iss,
      aud: opts.aud ?? "agentarb",
      iat: now - 10,
      exp: now + 3600,
      jti: freshJti(),
      grant: opts.grant,
      claims: {
        scope: opts.scope ?? ["agentarb:hold"],
        amount_limit: opts.amount,
        currency: opts.currency ?? "USD",
        task: "x",
      },
    },
    signerKp.privateJwk,
  );
}

/** An honest owner→agent chain with the product's mandate shape. */
function honestMandate(amount: number, over: Record<string, unknown> = {}) {
  const owner = generateKeypair();
  const agent = generateKeypair();
  const g = grantJws(owner, {
    iss: owner.did,
    sub: agent.did,
    amount: 100,
    scope: (over.grantScope as string[] | undefined) ?? ["agentarb:hold"],
    currency: (over.grantCurrency as string | undefined) ?? "USD",
  });
  const m = mandateJws(agent, {
    iss: agent.did,
    aud: (over.aud as string | undefined) ?? "agentarb",
    amount,
    scope: (over.scope as string[] | undefined) ?? ["agentarb:hold"],
    currency: (over.currency as string | undefined) ?? "USD",
    grant: g,
  });
  return { mandate: m, agent };
}

test("escrow: honest mandate backs a hold; agent is the mandate agent", () => {
  const { mandate, agent } = honestMandate(50);
  const c = checkMandateForHold(mandate, 5000, "USD");
  assert.equal(c.ok, true, c.reason);
  assert.equal(c.agent, agent.did);
  assert.equal(c.amount_limit_minor, 5000);
});

test("escrow: forged mandate (attacker key, victim iss/sub) is rejected on kid binding", () => {
  // C1, exact judge repro shape — but with the product's scope/audience/
  // currency, so the ONLY thing that catches it is the kid binding.
  const attacker = generateKeypair();
  const victimAgent = generateKeypair();
  const victimOwner = generateKeypair().did;
  const g = grantJws(attacker, {
    iss: victimOwner,
    sub: victimAgent.did,
    amount: 1000000,
  });
  const m = mandateJws(attacker, {
    iss: victimAgent.did,
    amount: 999999,
    grant: g,
  });
  const c = checkMandateForHold(m, 99999900, "USD");
  assert.equal(c.ok, false);
  assert.match(c.reason || "", /kid does not match/);
});

test("escrow: mandate limit floors to minor units (no round-up)", () => {
  // m4: 0.125 major = 12.5 minor must floor to 12, never back 13.
  const { mandate } = honestMandate(0.125);
  const over = checkMandateForHold(mandate, 13, "USD");
  assert.equal(over.ok, false);
  assert.match(over.reason || "", /exceeds mandate limit 12/);
  const { mandate: m2 } = honestMandate(0.125);
  const at = checkMandateForHold(m2, 12, "USD");
  assert.equal(at.ok, true, at.reason);
});

test("escrow: mandate for another audience cannot back an AgentArb hold", () => {
  // m5
  const { mandate } = honestMandate(50, { aud: "totally-different-service" });
  const c = checkMandateForHold(mandate, 5000, "USD");
  assert.equal(c.ok, false);
});

test("escrow: EUR mandate cannot back a USD hold", () => {
  // m6
  const { mandate } = honestMandate(50, {
    currency: "EUR",
    grantCurrency: "EUR",
  });
  const c = checkMandateForHold(mandate, 5000, "USD");
  assert.equal(c.ok, false);
  assert.match(c.reason || "", /currency/);
});

test("escrow: mandate without agentarb:hold scope is rejected", () => {
  // m7 scope half: any agent may back a hold (guarantor model), but the
  // mandate must actually authorize AgentArb holds.
  const { mandate } = honestMandate(50, { scope: ["task"] });
  const c = checkMandateForHold(mandate, 5000, "USD");
  assert.equal(c.ok, false);
  assert.match(c.reason || "", /scope/);
});

test("escrow: downward revision that zeroes a hold marks it released", () => {
  // m10: the release path used to preserve hold.status, leaving a
  // zero-balance hold "held".
  const s = new Store(":memory:");
  const at = new Date().toISOString();
  try {
    s.createHold("h1", "c1", 0, 10000, "USD", null, null, at);
    s.createHold("h2", "c1", 0, 5000, "USD", null, null, at);
    applyVerdictToEscrow(s, "c1", 0, "v1", "refund_full", 10000, at, 10000);
    assert.equal(s.getHold("h1")?.status, "refunded");
    const fx = applyVerdictToEscrow(s, "c1", 0, "v2", "refund_partial", 3000, at, 10000);
    const rel = fx.filter((e) => e.kind === "release");
    assert.equal(rel.reduce((a, e) => a + e.amount_minor, 0), 5000);
    assert.equal(s.getHold("h2")?.remaining_minor, 0);
    assert.equal(s.getHold("h2")?.status, "released");
    assert.equal(rel[0].hold_status, "released");
  } finally {
    s.close();
  }
});

test("escrow: hold created after a refund verdict funds the shortfall", () => {
  // m11: applied tracks the verdict (10000) while cumulative tracks cash
  // (0) when no hold existed; a later hold must fund the shortfall
  // instead of sitting "held" forever.
  const s = new Store(":memory:");
  const at = new Date().toISOString();
  try {
    s.saveVerdict("v1", "c1", 0, { id: "v1" }, "rules", "refund_full", 10000, at);
    applyVerdictToEscrow(s, "c1", 0, "v1", "refund_full", 10000, at, 10000);
    assert.equal(s.getAppliedRefund("c1", 0), 10000);
    assert.equal(s.getCumulativeRefund("c1", 0), 0);
    s.createHold("h1", "c1", 0, 4000, "USD", null, null, at);
    const fx = applyUnfundedRefund(s, "c1", 0, "h1", at);
    assert.equal(fx.length, 1);
    assert.equal(fx[0].kind, "refund");
    assert.equal(fx[0].amount_minor, 4000);
    assert.equal(fx[0].verdict_id, "v1");
    assert.equal(s.getHold("h1")?.status, "refunded");
    assert.equal(s.getCumulativeRefund("c1", 0), 4000);
    // A second hold funds the remaining shortfall, capped at its balance.
    s.createHold("h2", "c1", 0, 10000, "USD", null, null, at);
    const fx2 = applyUnfundedRefund(s, "c1", 0, "h2", at);
    assert.equal(fx2[0].amount_minor, 6000);
    assert.equal(s.getHold("h2")?.remaining_minor, 4000);
    assert.equal(s.getHold("h2")?.status, "held");
    assert.equal(s.getCumulativeRefund("c1", 0), 10000);
    // Nothing left owed: a third hold is untouched.
    s.createHold("h3", "c1", 0, 1000, "USD", null, null, at);
    assert.deepEqual(applyUnfundedRefund(s, "c1", 0, "h3", at), []);
    assert.equal(s.getHold("h3")?.status, "held");
  } finally {
    s.close();
  }
});
