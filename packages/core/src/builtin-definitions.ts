// packages/core/src/builtin-definitions.ts
//
// Source of truth for the three built-in rule sets. These are UNSIGNED
// definitions; scripts/sign-rulesets.mjs signs them and emits
// builtin-rulesets.generated.ts, which is what ships. Re-signing requires
// the built-in signing key (or a new keypair + updating BUILTIN_SIGNER_DID
// in the generated file).
//
// Rule evaluation context (built by the engine, see engine.ts):
//   claim: { type, amount_minor, penalty_minor|null, missing_minor|null,
//            delivered_fraction: {numerator, denominator}|null }
//   tx: { amount_minor, currency, agreed_delivery_at_epoch: number|null }
//   now_epoch: number
//   evidence: [{ id, kind, tier, delivered_at_epoch: number|null }]
//   delivery: { count, max_tier, earliest_epoch: number|null,
//               has_credible: boolean, has_any: boolean }
//   condition: { count, max_tier, has_credible: boolean }
//
// Rules are evaluated in order; the first matching rule decides. If no
// rule matches, the engine escalates ("I don't know").

import type { Ruleset } from "./rulesets.js";

export const BUILTIN_RULESET_DEFS: Ruleset[] = [
  {
    format: "agentarb-ruleset",
    id: "builtin/non-delivery",
    version: 1,
    claim_type: "non-delivery",
    description:
      "Claimant says nothing arrived. Refunds in full only when no delivery proof exists at all and the agreed deadline has passed; credible delivery proof defeats the claim; weak-only proof escalates.",
    min_evidence_tier: 1,
    rules: [
      {
        name: "credible-delivery-exists",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "non-delivery"] },
            { var: "delivery.has_credible" },
          ],
        },
        outcome: "reject",
        reason:
          "Credible delivery proof exists (tier >= 2); the non-delivery claim fails.",
      },
      {
        name: "weak-delivery-claim",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "non-delivery"] },
            { var: "delivery.has_any" },
            { "!": { var: "delivery.has_credible" } },
          ],
        },
        outcome: "escalate",
        reason:
          "Only weak (self-signed) delivery evidence exists; a human must weigh it.",
      },
      {
        name: "no-agreed-delivery-time",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "non-delivery"] },
            { "==": [{ var: "tx.agreed_delivery_at_epoch" }, null] },
          ],
        },
        outcome: "escalate",
        reason:
          "No agreed delivery time, so non-delivery cannot be time-boxed.",
      },
      {
        name: "delivery-window-open",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "non-delivery"] },
            { "<=": [{ var: "now_epoch" }, { var: "tx.agreed_delivery_at_epoch" }] },
          ],
        },
        outcome: "escalate",
        reason: "The agreed delivery window is still open; the claim is premature.",
      },
      {
        name: "no-delivery-past-deadline",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "non-delivery"] },
            { "!": { var: "delivery.has_any" } },
            { ">": [{ var: "now_epoch" }, { var: "tx.agreed_delivery_at_epoch" }] },
          ],
        },
        outcome: "refund_full",
        reason:
          "No delivery proof at all and the agreed deadline has passed.",
      },
    ],
  },
  {
    format: "agentarb-ruleset",
    id: "builtin/late-delivery",
    version: 1,
    claim_type: "late-delivery",
    description:
      "Claimant says delivery arrived after the agreed time. Compares the earliest credible delivery timestamp against the deadline; refunds the pre-agreed penalty when late.",
    min_evidence_tier: 2,
    rules: [
      {
        name: "no-agreed-delivery-time",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "late-delivery"] },
            { "==": [{ var: "tx.agreed_delivery_at_epoch" }, null] },
          ],
        },
        outcome: "escalate",
        reason: "No agreed delivery time, so lateness cannot be judged.",
      },
      {
        name: "no-credible-delivery-time",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "late-delivery"] },
            { "==": [{ var: "delivery.earliest_epoch" }, null] },
          ],
        },
        outcome: "escalate",
        reason:
          "No credible delivery timestamp to compare against the deadline.",
      },
      {
        name: "delivered-on-time",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "late-delivery"] },
            { "<=": [{ var: "delivery.earliest_epoch" }, { var: "tx.agreed_delivery_at_epoch" }] },
          ],
        },
        outcome: "reject",
        reason: "Earliest credible delivery was at or before the deadline.",
      },
      {
        name: "zero-penalty",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "late-delivery"] },
            { ">": [{ var: "delivery.earliest_epoch" }, { var: "tx.agreed_delivery_at_epoch" }] },
            { "==": [{ var: "claim.penalty_minor" }, 0] },
          ],
        },
        outcome: "reject",
        reason: "Delivery was late, but the agreed penalty is 0.",
      },
      {
        name: "delivered-late",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "late-delivery"] },
            { ">": [{ var: "delivery.earliest_epoch" }, { var: "tx.agreed_delivery_at_epoch" }] },
          ],
        },
        outcome: "refund_partial",
        reason:
          "Earliest credible delivery was after the deadline; the agreed penalty applies.",
      },
    ],
  },
  {
    format: "agentarb-ruleset",
    id: "builtin/wrong-partial-delivery",
    version: 1,
    claim_type: "wrong-partial-delivery",
    description:
      "Claimant says the delivery was wrong or partial. Requires credible condition evidence, then refunds the stated missing amount or the undelivered fraction.",
    min_evidence_tier: 2,
    rules: [
      {
        name: "no-credible-condition-evidence",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "wrong-partial-delivery"] },
            { "!": { var: "condition.has_credible" } },
          ],
        },
        outcome: "escalate",
        reason:
          "No credible condition evidence (inspection or oracle attestation at tier >= 2).",
      },
      {
        name: "nothing-missing",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "wrong-partial-delivery"] },
            { "==": [{ var: "claim.missing_minor" }, 0] },
            { "==": [{ var: "claim.delivered_fraction" }, null] },
          ],
        },
        outcome: "reject",
        reason: "Claim states nothing missing and no delivered fraction.",
      },
      {
        name: "fully-delivered",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "wrong-partial-delivery"] },
            { "!=": [{ var: "claim.delivered_fraction" }, null] },
            {
              "==": [
                { var: "claim.delivered_fraction.numerator" },
                { var: "claim.delivered_fraction.denominator" },
              ],
            },
          ],
        },
        outcome: "reject",
        reason: "Delivered fraction is whole; nothing is owed.",
      },
      {
        name: "missing-amount",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "wrong-partial-delivery"] },
            { "!=": [{ var: "claim.missing_minor" }, null] },
            { ">": [{ var: "claim.missing_minor" }, 0] },
          ],
        },
        outcome: "refund_partial",
        reason: "Credible condition evidence supports the stated missing amount.",
      },
      {
        name: "delivered-fraction",
        when: {
          and: [
            { "==": [{ var: "claim.type" }, "wrong-partial-delivery"] },
            { "!=": [{ var: "claim.delivered_fraction" }, null] },
          ],
        },
        outcome: "refund_partial",
        reason:
          "Credible condition evidence supports the delivered fraction; the undelivered share is refunded.",
      },
    ],
  },
];
