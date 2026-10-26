// packages/core/src/rulesets.ts
//
// Rule set format: versioned, content-addressed, signed. Every verdict
// cites the exact rule-set id/version/hash that decided it, so a verdict
// can be re-checked against the precise rules that produced it.
//
// A rule set's hash is SHA-256 of the canonical form of the rule set
// minus hash/signer/signature. Its signature is an Ed25519 JWS over that
// same payload, by the signer DID. Verification recomputes the hash,
// checks the signature covers the payload, and (when a trusted-signers
// list is given) requires the signer to be a member.
//
// Built-in rule sets ship in builtin-rulesets.generated.ts (produced by
// scripts/sign-rulesets.mjs from builtin-definitions.ts) and are loaded
// through builtin.ts, which verifies them against the embedded signer DID.

import { canonicalize, canonicalHashSync, CanonicalizationError } from "./jcs.js";
import { isDidKey } from "./did.js";
import { signJws, verifyJws, type Ed25519Jwk } from "./jws.js";
import type { ClaimType } from "./bundle.js";
import { MIN_TIER_FOR_CLAIM_TYPE } from "./bundle.js";
import type { JsonLogic } from "./rules.js";
import type { VerdictOutcome } from "./verdict.js";

export interface Rule {
  name: string;
  when: JsonLogic;
  outcome: VerdictOutcome;
  reason: string;
}

export interface Ruleset {
  format: "agentarb-ruleset";
  id: string;
  version: number;
  claim_type: ClaimType;
  description: string;
  min_evidence_tier: number;
  rules: Rule[];
}

export interface SignedRuleset extends Ruleset {
  hash: string;
  signer: string;
  signature: string;
}

/** The exact object a rule-set JWS signs (minus hash/signer/signature). */
export function rulesetSignPayload(
  rs: Ruleset,
): Record<string, unknown> {
  return {
    format: rs.format,
    id: rs.id,
    version: rs.version,
    claim_type: rs.claim_type,
    description: rs.description,
    min_evidence_tier: rs.min_evidence_tier,
    rules: rs.rules,
  };
}

export function hashRuleset(rs: Ruleset): string {
  return canonicalHashSync(rulesetSignPayload(rs));
}

export function signRuleset(
  rs: Ruleset,
  privateJwk: Ed25519Jwk,
): SignedRuleset {
  const payload = rulesetSignPayload(rs);
  const jws = signJws(payload, privateJwk);
  const verified = verifyJws(jws);
  if (!verified.ok) {
    throw new Error("failed to self-verify rule-set signature");
  }
  return {
    ...rs,
    hash: hashRuleset(rs),
    signer: verified.issuerDid as string,
    signature: jws,
  };
}

/** Structural validation of a signed rule set. Returns error strings. */
export function validateRuleset(rs: unknown): string[] {
  const errors: string[] = [];
  if (rs === null || typeof rs !== "object" || Array.isArray(rs)) {
    return ["rule set must be an object"];
  }
  const r = rs as Record<string, unknown>;
  if (r.format !== "agentarb-ruleset") errors.push("format must be 'agentarb-ruleset'");
  if (typeof r.id !== "string" || r.id.length === 0) errors.push("id must be a non-empty string");
  if (!Number.isSafeInteger(r.version) || (r.version as number) < 1) {
    errors.push("version must be a safe integer >= 1");
  }
  const claimTypes = ["non-delivery", "late-delivery", "wrong-partial-delivery"];
  if (!claimTypes.includes(r.claim_type as string)) {
    errors.push(`claim_type must be one of ${claimTypes.join(", ")}`);
  }
  if (typeof r.description !== "string" || r.description.length === 0) {
    errors.push("description must be a non-empty string");
  }
  if (
    typeof r.min_evidence_tier !== "number" ||
    ![0, 1, 2, 3].includes(r.min_evidence_tier)
  ) {
    errors.push("min_evidence_tier must be 0, 1, 2, or 3");
  } else if (
    claimTypes.includes(r.claim_type as string) &&
    (r.min_evidence_tier as number) !==
      MIN_TIER_FOR_CLAIM_TYPE[r.claim_type as ClaimType]
  ) {
    errors.push(
      `min_evidence_tier must equal the claim type floor (${MIN_TIER_FOR_CLAIM_TYPE[r.claim_type as ClaimType]} for ${r.claim_type})`,
    );
  }
  if (!Array.isArray(r.rules) || r.rules.length === 0) {
    errors.push("rules must be a non-empty array");
  } else {
    const outcomes = ["refund_full", "refund_partial", "reject", "escalate"];
    const names = new Set<string>();
    r.rules.forEach((rule: unknown, i: number) => {
      if (rule === null || typeof rule !== "object" || Array.isArray(rule)) {
        errors.push(`rules[${i}] must be an object`);
        return;
      }
      const ru = rule as Record<string, unknown>;
      if (typeof ru.name !== "string" || ru.name.length === 0) {
        errors.push(`rules[${i}].name must be a non-empty string`);
      } else if (names.has(ru.name)) {
        errors.push(`rules[${i}].name duplicates an earlier rule name`);
      } else {
        names.add(ru.name);
      }
      if (ru.when === undefined) errors.push(`rules[${i}].when is required`);
      if (!outcomes.includes(ru.outcome as string)) {
        errors.push(`rules[${i}].outcome must be one of ${outcomes.join(", ")}`);
      }
      if (typeof ru.reason !== "string" || ru.reason.length === 0) {
        errors.push(`rules[${i}].reason must be a non-empty string`);
      }
    });
  }
  if (typeof r.hash !== "string" || !/^[0-9a-f]{64}$/.test(r.hash)) {
    errors.push("hash must be a 64-hex-character digest");
  }
  if (!isDidKey(r.signer)) errors.push("signer must be an Ed25519 did:key");
  if (typeof r.signature !== "string" || r.signature.length === 0) {
    errors.push("signature must be a non-empty string");
  }
  return errors;
}

export interface RulesetVerification {
  ok: boolean;
  errors: string[];
}

/** Full verification: structure, hash recomputation, signature coverage. */
export function verifyRuleset(
  rs: unknown,
  opts: { trustedSigners?: string[] } = {},
): RulesetVerification {
  const errors = validateRuleset(rs);
  if (errors.length > 0) return { ok: false, errors };
  const r = rs as SignedRuleset;
  if (opts.trustedSigners && !opts.trustedSigners.includes(r.signer)) {
    errors.push(`signer ${r.signer} is not in the trusted set`);
  }
  // Library robustness: a hostile deeply-nested rule set must return
  // { ok: false }, never throw — canonicalization enforces a depth cap
  // and throws CanonicalizationError above it.
  try {
    if (hashRuleset(r) !== r.hash) {
      errors.push("hash does not match rule-set content");
    }
    const verified = verifyJws(r.signature, r.signer);
    if (!verified.ok) {
      errors.push(`signature invalid (${verified.reason})`);
      return { ok: false, errors };
    }
    if (canonicalize(verified.payload) !== canonicalize(rulesetSignPayload(r))) {
      errors.push("signature does not cover this rule set");
    }
  } catch (e) {
    if (e instanceof CanonicalizationError || e instanceof RangeError) {
      errors.push(`rule set cannot be canonicalized (${(e as Error).message})`);
      return { ok: false, errors };
    }
    throw e;
  }
  return { ok: errors.length === 0, errors };
}
