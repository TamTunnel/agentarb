// packages/core/src/engine.ts
//
// The adjudication engine: bundle + rule set -> verdict.
//
// Pipeline:
//   1. Verify the bundle (structure, envelope signatures, evidence
//      signatures). Anything invalid throws — the engine never rules on
//      an unverified bundle.
//   2. Split evidence per the claim type's minimum tier. Only admitted
//      evidence reaches the rules; excluded items are recorded.
//   3. Build the rule evaluation context (claim, transaction, admitted
//      evidence, delivery/condition summaries, now).
//   4. Evaluate the rule set's rules in order. The first matching rule
//      decides; the reasoning trace records every rule's matched flag.
//   5. No rule matching means "I don't know" -> escalate, refund 0.
//   6. Compute the refund for the winning outcome, enforcing the
//      invariant refund <= claim amount. A computed refund above the
//      claim escalates instead of silently clamping.
//
// Verdicts are signed by the caller (the arbiter service holds the key);
// the engine returns the unsigned verdict with its content-addressed id,
// plus the trace and evidence split, so the caller can sign and store it.

import {
  filterEvidenceForClaim,
  verifyBundle,
  type Bundle,
  type Claim,
  type VerifiedEvidence,
} from "./bundle.js";
import { evaluate, RuleError } from "./rules.js";
import type { SignedRuleset } from "./rulesets.js";
import {
  refundForDeliveredFraction,
} from "./money.js";
import {
  verdictIdFor,
  verdictSignPayload,
  type ReasoningStep,
  type Verdict,
  type VerdictOutcome,
} from "./verdict.js";

export interface EngineContext {
  claim: {
    type: string;
    amount_minor: number;
    penalty_minor: number | null;
    missing_minor: number | null;
    delivered_fraction: { numerator: number; denominator: number } | null;
  };
  tx: {
    amount_minor: number;
    currency: string;
    agreed_delivery_at_epoch: number | null;
  };
  now_epoch: number;
  evidence: Array<{
    id: string;
    kind: string;
    tier: number;
    delivered_at_epoch: number | null;
  }>;
  delivery: {
    count: number;
    max_tier: number;
    earliest_epoch: number | null;
    has_credible: boolean;
    has_any: boolean;
  };
  condition: {
    count: number;
    max_tier: number;
    has_credible: boolean;
  };
}

function epochOrNull(iso: string | null | undefined): number | null {
  if (iso == null) return null;
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return null;
  return Math.floor(ms / 1000);
}

export function buildContext(
  bundle: Bundle,
  claim: Claim,
  admitted: VerifiedEvidence[],
  now: Date,
): EngineContext {
  const deliveryProofs = admitted.filter(
    (v) => v.item.kind === "delivery-proof",
  );
  const deliveryEpochs = deliveryProofs
    .map((v) => epochOrNull(v.item.delivered_at))
    .filter((e): e is number => e !== null);
  const conditionProofs = admitted.filter(
    (v) => v.item.kind === "condition-proof" || v.item.kind === "oracle-attestation",
  );
  const frac = claim.details.delivered_fraction as
    | { numerator: number; denominator: number }
    | undefined;
  return {
    claim: {
      type: claim.type,
      amount_minor: claim.amount_minor,
      penalty_minor:
        typeof claim.details.penalty_minor === "number"
          ? claim.details.penalty_minor
          : null,
      missing_minor:
        typeof claim.details.missing_minor === "number"
          ? claim.details.missing_minor
          : null,
      delivered_fraction:
        frac !== undefined &&
        typeof frac.numerator === "number" &&
        typeof frac.denominator === "number"
          ? { numerator: frac.numerator, denominator: frac.denominator }
          : null,
    },
    tx: {
      amount_minor: bundle.transaction.amount_minor,
      currency: bundle.transaction.currency,
      agreed_delivery_at_epoch: epochOrNull(
        bundle.transaction.agreed_delivery_at,
      ),
    },
    now_epoch: Math.floor(now.getTime() / 1000),
    evidence: admitted.map((v) => ({
      id: v.item.id,
      kind: v.item.kind,
      tier: v.tier,
      delivered_at_epoch: epochOrNull(v.item.delivered_at),
    })),
    delivery: {
      count: deliveryProofs.length,
      max_tier: deliveryProofs.reduce((m, v) => Math.max(m, v.tier), 0),
      earliest_epoch:
        deliveryEpochs.length > 0 ? Math.min(...deliveryEpochs) : null,
      has_credible: deliveryProofs.some((v) => v.tier >= 2),
      has_any: deliveryProofs.length > 0,
    },
    condition: {
      count: conditionProofs.length,
      max_tier: conditionProofs.reduce((m, v) => Math.max(m, v.tier), 0),
      has_credible: conditionProofs.some((v) => v.tier >= 2),
    },
  };
}

export interface Adjudication {
  verdict: Verdict;
  context: EngineContext;
  admitted: VerifiedEvidence[];
  excluded: Array<{ id: string; tier: number; reason: string }>;
  firedRule: string | null;
}

function computeRefund(
  outcome: VerdictOutcome,
  claim: Claim,
  context: EngineContext,
): { refund: number } | { escalate: string } {
  if (outcome === "refund_full") {
    return { refund: claim.amount_minor };
  }
  if (outcome === "refund_partial") {
    if (claim.type === "late-delivery") {
      const penalty = context.claim.penalty_minor;
      if (penalty === null) return { escalate: "late-delivery refund needs penalty_minor" };
      return { refund: penalty };
    }
    if (claim.type === "wrong-partial-delivery") {
      if (
        context.claim.missing_minor !== null &&
        context.claim.missing_minor > 0
      ) {
        return { refund: context.claim.missing_minor };
      }
      const frac = context.claim.delivered_fraction;
      if (frac !== null) {
        const refund = refundForDeliveredFraction(
          context.tx.amount_minor,
          frac.numerator,
          frac.denominator,
        );
        if (refund > claim.amount_minor) {
          return {
            escalate:
              "computed fraction refund exceeds the claimed amount; human must reconcile",
          };
        }
        return { refund };
      }
      return { escalate: "wrong-partial refund needs missing_minor or delivered_fraction" };
    }
    return { escalate: `refund_partial has no amount rule for ${claim.type}` };
  }
  return { refund: 0 };
}

/**
 * Adjudicate one claim of a verified bundle under one rule set.
 * `caseId` labels the verdict; `now` defaults to the current time and is
 * an explicit parameter so determinism can be tested (same bundle + same
 * rules + same now = byte-identical verdict).
 */
export function adjudicateClaim(
  bundle: Bundle,
  claimIndex: number,
  ruleset: SignedRuleset,
  caseId: string,
  arbiterDid: string,
  now: Date = new Date(),
): Adjudication {
  const claim = bundle.claims[claimIndex];
  if (!claim) {
    throw new Error(`claim index ${claimIndex} out of range`);
  }
  if (claim.type !== ruleset.claim_type) {
    throw new Error(
      `rule set ${ruleset.id} covers ${ruleset.claim_type}, not ${claim.type}`,
    );
  }
  const verified = verifyBundle(bundle);
  if (!verified.ok) {
    throw new Error(
      `cannot adjudicate unverified bundle: ${verified.errors.join("; ")}`,
    );
  }
  const { admitted, excluded } = filterEvidenceForClaim(
    verified.evidence,
    claim.type,
  );
  const context = buildContext(bundle, claim, admitted, now);

  const reasoning: ReasoningStep[] = [];
  let firedRule: string | null = null;
  let outcome: VerdictOutcome = "escalate";
  for (const rule of ruleset.rules) {
    let matched: boolean;
    try {
      matched = !!evaluate(rule.when, context);
    } catch (e) {
      if (e instanceof RuleError) {
        throw new Error(`rule ${rule.name} failed to evaluate: ${e.message}`);
      }
      throw e;
    }
    reasoning.push({
      rule: rule.name,
      matched,
      reason: matched
        ? rule.reason
        : `rule did not match (${rule.reason})`,
    });
    if (matched) {
      firedRule = rule.name;
      outcome = rule.outcome;
      break;
    }
  }
  if (firedRule === null) {
    reasoning.push({
      rule: "fallback",
      matched: true,
      reason: "No rule matched; the engine cannot decide — escalating to a human.",
    });
  }

  let refund = 0;
  if (outcome === "refund_full" || outcome === "refund_partial") {
    const computed = computeRefund(outcome, claim, context);
    if ("escalate" in computed) {
      outcome = "escalate";
      firedRule = null;
      reasoning.push({
        rule: "refund-guard",
        matched: true,
        reason: computed.escalate,
      });
    } else {
      refund = computed.refund;
    }
  }
  if (refund > claim.amount_minor) {
    outcome = "escalate";
    refund = 0;
    reasoning.push({
      rule: "refund-guard",
      matched: true,
      reason: "computed refund exceeds the claimed amount; escalating",
    });
  }

  const decidedAt = now.toISOString();
  const verdictCore = {
    format: "agentarb-verdict" as const,
    version: 1 as const,
    case_id: caseId,
    bundle_id: bundle.id,
    bundle_hash: verified.hash as string,
    ruleset_id: ruleset.id,
    ruleset_version: ruleset.version,
    ruleset_hash: ruleset.hash,
    method: "rules" as const,
    outcome,
    refund_minor: refund,
    currency: bundle.transaction.currency,
    claim_amount_minor: claim.amount_minor,
    reasoning,
    decided_at: decidedAt,
    arbiter: arbiterDid,
  };
  const id = verdictIdFor(verdictSignPayload(verdictCore));
  const verdict: Verdict = { ...verdictCore, id, signature: null };
  return { verdict, context, admitted, excluded, firedRule };
}
