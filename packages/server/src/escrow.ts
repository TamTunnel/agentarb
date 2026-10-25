// packages/server/src/escrow.ts
//
// Verdict-gated escrow: a ledger adapter, NOT custody. Holds are records
// of amounts frozen for a case; verdicts move them. No real money moves
// in v1 — the ledger is the demo/test model that Stripe/on-chain adapters
// will settle against later (the verdict format is already final, so
// adapters slot in without changing it).
//
// Two hold kinds:
//   - plain: created directly with an amount (demo/test use).
//   - mandate-backed: created from an AgentCred task mandate, verified
//     with the audited @tamtunnel/si-wallet-core verifyMandate. The
//     mandate's amount_limit (major units) must cover the hold amount,
//     and verification CONSUMES the mandate's jti in the server's replay
//     ledger (SI_WALLET_DIR = the server data dir), so a mandate backs
//     exactly one hold — re-submission fails as a replay.
//
// Applying a verdict (including re-adjudication) moves only the DELTA
// between the verdict's refund and what was already applied for that
// claim: positive deltas refund more, negative deltas release back.
// Escalate verdicts move nothing. Reject verdicts release the remaining
// hold (the respondent keeps it). Total cash refunded per claim is capped
// at the claim amount across ALL verdicts: a reject resets the applied
// level but never the cumulative refunded figure, so a refund → reject →
// new hold → refund sequence cannot pay a claim twice.

import { verifyMandate } from "@tamtunnel/si-wallet-core";
import type { Store } from "./store.js";

export interface EscrowEffect {
  hold_id: string;
  kind: "refund" | "release" | "none";
  amount_minor: number;
  verdict_id: string;
  remaining_minor: number;
  hold_status: string;
}

export interface MandateHoldCheck {
  ok: boolean;
  reason?: string;
  agent?: string;
  amount_limit_minor?: number;
}

/**
 * Verify an AgentCred mandate for a hold. The mandate amount_limit is in
 * major units; the hold amount is in minor units. Currency is NOT
 * constrained by the mandate in v1 (AgentCred mandates carry a currency
 * claim in newer versions; this adapter treats amount_limit as major
 * units in the hold's currency and says so).
 */
export function checkMandateForHold(
  mandateJws: string,
  amountMinor: number,
): MandateHoldCheck {
  let result;
  try {
    result = verifyMandate({ mandateJws });
  } catch (e) {
    return { ok: false, reason: "mandate verification threw: " + (e as Error).message };
  }
  if (!result.ok) {
    return { ok: false, reason: result.reason };
  }
  const limitMinor = Math.round((result.amount_limit ?? 0) * 100);
  if (amountMinor > limitMinor) {
    return {
      ok: false,
      reason: `hold amount ${amountMinor} exceeds mandate limit ${limitMinor} minor units`,
    };
  }
  return { ok: true, agent: result.agent, amount_limit_minor: limitMinor };
}

/**
 * Apply one verdict's refund to a case's holds, moving only the delta
 * versus what was already applied for this claim. Returns the effects.
 *
 * Two figures are tracked per claim, and they mean different things:
 *   - applied: the latest verdict's refund level (for delta math).
 *   - cumulative: cash actually refunded across ALL verdicts. It never
 *     decreases and a reject never resets it — so a refund → reject →
 *     new hold → refund sequence cannot pay a claim twice. Refund
 *     movement is capped at claimAmountMinor minus cumulative.
 */
export function applyVerdictToEscrow(
  store: Store,
  caseId: string,
  claimIndex: number,
  verdictId: string,
  outcome: string,
  refundMinor: number,
  now: string,
  claimAmountMinor: number,
): EscrowEffect[] {
  const effects: EscrowEffect[] = [];
  if (outcome === "escalate") return effects;
  const previouslyApplied = store.getAppliedRefund(caseId, claimIndex);
  // Holds are scoped per claim: a verdict moves only its own claim's
  // holds, so a reject on one claim can never drain another claim's hold.
  const holds = store
    .getHolds(caseId)
    .filter((h) => h.status === "held" && h.claim_index === claimIndex);
  if (outcome === "reject") {
    // Release everything still held for this claim.
    for (const hold of holds) {
      const amount = hold.remaining_minor;
      if (amount <= 0) continue;
      store.addHoldEvent(hold.id, "release", amount, verdictId, now);
      store.updateHold(hold.id, 0, "released", now);
      effects.push({
        hold_id: hold.id,
        kind: "release",
        amount_minor: amount,
        verdict_id: verdictId,
        remaining_minor: 0,
        hold_status: "released",
      });
    }
    store.setAppliedRefund(caseId, claimIndex, 0);
    // Deliberately NOT resetting the cumulative figure: money already
    // refunded stays refunded. A later refund verdict is capped by it.
    return effects;
  }
  // refund_full / refund_partial
  const delta = refundMinor - previouslyApplied;
  if (delta === 0) return effects;
  if (delta < 0) {
    // New verdict refunds less than before: release the difference.
    let toRelease = -delta;
    for (const hold of holds) {
      if (toRelease <= 0) break;
      const amount = Math.min(toRelease, hold.remaining_minor);
      if (amount <= 0) continue;
      store.addHoldEvent(hold.id, "release", amount, verdictId, now);
      store.updateHold(hold.id, hold.remaining_minor - amount, hold.status, now);
      toRelease -= amount;
      effects.push({
        hold_id: hold.id,
        kind: "release",
        amount_minor: amount,
        verdict_id: verdictId,
        remaining_minor: hold.remaining_minor - amount,
        hold_status: hold.status,
      });
    }
    store.setAppliedRefund(caseId, claimIndex, refundMinor);
    return effects;
  }
  // delta > 0: refund more, drawing from held balances — but never more
  // than the claim's remaining headroom: claim amount minus cash already
  // refunded across all verdicts (including across rejects).
  const cumulative = store.getCumulativeRefund(caseId, claimIndex);
  const headroom = Math.max(0, claimAmountMinor - cumulative);
  let toRefund = Math.min(delta, headroom);
  let refunded = 0;
  for (const hold of holds) {
    if (toRefund <= 0) break;
    const amount = Math.min(toRefund, hold.remaining_minor);
    if (amount <= 0) continue;
    const remaining = hold.remaining_minor - amount;
    store.addHoldEvent(hold.id, "refund", amount, verdictId, now);
    store.updateHold(hold.id, remaining, remaining === 0 ? "refunded" : "held", now);
    toRefund -= amount;
    refunded += amount;
    effects.push({
      hold_id: hold.id,
      kind: "refund",
      amount_minor: amount,
      verdict_id: verdictId,
      remaining_minor: remaining,
      hold_status: remaining === 0 ? "refunded" : "held",
    });
  }
  if (refunded > 0) {
    store.addCumulativeRefund(caseId, claimIndex, refunded);
  }
  // If holds did not cover the delta (e.g. no hold exists), the verdict
  // still stands — the ledger records what moved, and the shortfall is
  // visible as applied < refund. The applied figure tracks verdicts,
  // not cash: set it to the verdict's refund so re-adjudication deltas
  // stay correct even when no hold covers them.
  store.setAppliedRefund(caseId, claimIndex, refundMinor);
  return effects;
}
