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
 * Decode a compact JWS's header and payload WITHOUT verifying the
 * signature. Used only for binding checks that run before (or alongside)
 * si-wallet-core verification: the decoded content is never trusted on
 * its own — verifyMandate still verifies the signatures over these exact
 * bytes before any hold is created.
 */
function decodeJwsParts(
  jws: string,
): { kidDid: string; payload: Record<string, unknown> } | null {
  try {
    const parts = (jws || "").split(".");
    if (parts.length !== 3) return null;
    const header = JSON.parse(
      Buffer.from(parts[0], "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    if (
      header === null ||
      typeof header !== "object" ||
      Array.isArray(header) ||
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload)
    ) {
      return null;
    }
    const kidDid = String(header.kid || "").split("#")[0];
    if (!kidDid) return null;
    return { kidDid, payload };
  } catch {
    return null;
  }
}

/**
 * Verify an AgentCred mandate for a hold. The mandate amount_limit is in
 * major units; the hold amount is in minor units.
 *
 * Adapter-side hardening beyond what si-wallet-core's verifyMandate
 * checks (chain shape, expiry, sub==iss, scope/amount narrowing, jti
 * replay):
 *   - KID BINDING (closed upstream in si-wallet-core 0.1.1): verifyMandate
 *     used to never bind a JWS kid to the identity it claims to be, so an
 *     attacker holding only their own key could mint a grant (iss=victim
 *     owner, sub=victim agent) and a mandate (iss=victim agent) that
 *     verified as the victim. This adapter requires kid-DID == iss for
 *     BOTH the mandate and the embedded grant, and re-asserts grant sub
 *     == mandate iss. These checks run BEFORE verifyMandate so a policy
 *     rejection never burns the mandate's jti in the replay ledger. Kept
 *     as defense in depth now that upstream binds kid itself.
 *   - Audience: the mandate must be minted for "agentarb".
 *   - Currency: the mandate's claims.currency must equal the hold
 *     currency (a mandate without a currency claim is rejected).
 *   - Scope: the mandate's claims.scope must include "agentarb:hold".
 *     Any agent may back a hold (guarantor model — the mandate proves
 *     spending authority, not party membership); party matching is
 *     deliberately NOT enforced.
 *   - Rounding: the major→minor conversion floors, never rounds up, so
 *     a limit like 0.125 major can never back a 13-minor hold.
 */
export function checkMandateForHold(
  mandateJws: string,
  amountMinor: number,
  currency: string,
): MandateHoldCheck {
  // Policy checks first (decode-only, fail-closed): they never trust
  // unverified content, because the same bytes are signature-verified
  // by verifyMandate below before any hold is created — and running
  // them first means a rejected mandate keeps its jti unburned.
  const mandateParts = decodeJwsParts(mandateJws);
  if (!mandateParts) {
    return { ok: false, reason: "mandate JWS is not decodable" };
  }
  const mandatePayload = mandateParts.payload;
  if (mandateParts.kidDid !== mandatePayload.iss) {
    return {
      ok: false,
      reason: "mandate JWS kid does not match mandate iss (kid/issuer binding)",
    };
  }
  const grantJws = mandatePayload.grant;
  if (typeof grantJws !== "string") {
    return { ok: false, reason: "mandate carries no embedded grant JWS" };
  }
  const grantParts = decodeJwsParts(grantJws);
  if (!grantParts) {
    return { ok: false, reason: "grant JWS is not decodable" };
  }
  if (grantParts.kidDid !== grantParts.payload.iss) {
    return {
      ok: false,
      reason: "grant JWS kid does not match grant iss (kid/issuer binding)",
    };
  }
  if (grantParts.payload.sub !== mandatePayload.iss) {
    return {
      ok: false,
      reason: "grant sub does not match mandate iss",
    };
  }
  const claims = mandatePayload.claims as Record<string, unknown> | undefined;
  const mandateCurrency = claims?.currency;
  if (typeof mandateCurrency !== "string" || mandateCurrency.length === 0) {
    return { ok: false, reason: "mandate carries no currency claim" };
  }
  if (mandateCurrency !== currency) {
    return {
      ok: false,
      reason: `mandate currency ${mandateCurrency} does not match hold currency ${currency}`,
    };
  }
  const scope = claims?.scope;
  if (!Array.isArray(scope) || !scope.includes("agentarb:hold")) {
    return {
      ok: false,
      reason: `mandate scope does not include "agentarb:hold"`,
    };
  }
  let result;
  try {
    result = verifyMandate({ mandateJws, expectedAudience: "agentarb" });
  } catch (e) {
    return { ok: false, reason: "mandate verification threw: " + (e as Error).message };
  }
  if (!result.ok) {
    return { ok: false, reason: result.reason };
  }
  const limitMinor = Math.floor((result.amount_limit ?? 0) * 100);
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
  if (delta === 0) {
    // Self-healing for holds created after this verdict was applied:
    // applied tracks the verdict level while cumulative tracks cash, so
    // a hold that arrived after the verdict leaves applied > cumulative.
    // Fund that shortfall from held balances now (bounded by the claim
    // headroom, same as the normal refund path) instead of leaving the
    // new hold "held" forever. In the normal case the shortfall is 0
    // and this is a no-op.
    const cumulative = store.getCumulativeRefund(caseId, claimIndex);
    const headroom = Math.max(0, claimAmountMinor - cumulative);
    let toRefund = Math.min(previouslyApplied - cumulative, headroom);
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
    return effects;
  }
  if (delta < 0) {
    // New verdict refunds less than before: release the difference.
    let toRelease = -delta;
    for (const hold of holds) {
      if (toRelease <= 0) break;
      const amount = Math.min(toRelease, hold.remaining_minor);
      if (amount <= 0) continue;
      const remaining = hold.remaining_minor - amount;
      // A release that zeroes the balance ends the hold: leaving it
      // "held" at remaining 0 would strand a dead record.
      const status = remaining === 0 ? "released" : hold.status;
      store.addHoldEvent(hold.id, "release", amount, verdictId, now);
      store.updateHold(hold.id, remaining, status, now);
      toRelease -= amount;
      effects.push({
        hold_id: hold.id,
        kind: "release",
        amount_minor: amount,
        verdict_id: verdictId,
        remaining_minor: remaining,
        hold_status: status,
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
  // visible as cumulative < applied: applied equals the verdict's
  // refund level, cumulative is the cash actually moved. The applied
  // figure tracks verdicts, not cash: set it to the verdict's refund so
  // re-adjudication deltas stay correct even when no hold covers them.
  // A hold created later funds the shortfall immediately via
  // applyUnfundedRefund (called by the holds endpoint), so the shortfall
  // never strands funds on a newly created hold.
  store.setAppliedRefund(caseId, claimIndex, refundMinor);
  return effects;
}

/**
 * Fund a refund shortfall from a newly created hold. When a refund
 * verdict was applied before any hold existed, applied > cumulative and
 * the verdict's cash is outstanding; without this, a hold created after
 * the verdict would sit "held" forever (re-applying the same verdict is
 * a delta-0 no-op by design). The refund is capped at the shortfall and
 * at the hold's balance, is attributed to the claim's latest verdict,
 * and updates the cumulative figure — it can never over-pay, because
 * the shortfall itself is bounded by the verdict level minus cash
 * already moved. Returns the effects (empty when nothing is owed).
 */
export function applyUnfundedRefund(
  store: Store,
  caseId: string,
  claimIndex: number,
  holdId: string,
  now: string,
): EscrowEffect[] {
  const applied = store.getAppliedRefund(caseId, claimIndex);
  const cumulative = store.getCumulativeRefund(caseId, claimIndex);
  const shortfall = applied - cumulative;
  if (shortfall <= 0) return [];
  const hold = store.getHold(holdId);
  if (!hold || hold.status !== "held" || hold.remaining_minor <= 0) return [];
  const verdicts = store
    .getVerdicts(caseId)
    .filter((v) => v.claim_index === claimIndex);
  const latest = verdicts[verdicts.length - 1];
  if (!latest) return [];
  const amount = Math.min(shortfall, hold.remaining_minor);
  const remaining = hold.remaining_minor - amount;
  store.addHoldEvent(holdId, "refund", amount, latest.id, now);
  store.updateHold(holdId, remaining, remaining === 0 ? "refunded" : "held", now);
  store.addCumulativeRefund(caseId, claimIndex, amount);
  return [
    {
      hold_id: holdId,
      kind: "refund",
      amount_minor: amount,
      verdict_id: latest.id,
      remaining_minor: remaining,
      hold_status: remaining === 0 ? "refunded" : "held",
    },
  ];
}
